using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Dynamic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace CB.Web.Security
{
    internal class Database : IDisposable
    {
        public sealed class DynamicRecord : DynamicObject, ICustomTypeDescriptor
        {
            internal DynamicRecord(IEnumerable<string> columnNames, IDataRecord record)
            {
                Debug.Assert(record != null, "record should not be null");
                Debug.Assert(columnNames != null, "columnNames should not be null");

                Columns = columnNames.ToList();
                Record = record;
            }

            public IList<string> Columns { get; private set; }

            private IDataRecord Record { get; set; }

            public object this[string name]
            {
                get
                {
                    VerifyColumn(name);
                    return GetValue(Record[name]);
                }
            }

            public object this[int index]
            {
                get { return GetValue(Record[index]); }
            }

            public override bool TryGetMember(GetMemberBinder binder, out object result)
            {
                result = this[binder.Name];
                return true;
            }

            private static object GetValue(object value)
            {
                return DBNull.Value == value ? null : value;
            }

            public override IEnumerable<string> GetDynamicMemberNames()
            {
                return Columns;
            }

            private void VerifyColumn(string name)
            {
                // REVIEW: Perf
                if (!Columns.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        String.Format(CultureInfo.CurrentCulture,
                                      "InvalidColumnName {0}", name));
                }
            }

            AttributeCollection ICustomTypeDescriptor.GetAttributes()
            {
                return AttributeCollection.Empty;
            }

            string ICustomTypeDescriptor.GetClassName()
            {
                return null;
            }

            string ICustomTypeDescriptor.GetComponentName()
            {
                return null;
            }

            TypeConverter ICustomTypeDescriptor.GetConverter()
            {
                return null;
            }

            EventDescriptor ICustomTypeDescriptor.GetDefaultEvent()
            {
                return null;
            }

            PropertyDescriptor ICustomTypeDescriptor.GetDefaultProperty()
            {
                return null;
            }

            object ICustomTypeDescriptor.GetEditor(Type editorBaseType)
            {
                return null;
            }

            EventDescriptorCollection ICustomTypeDescriptor.GetEvents(Attribute[] attributes)
            {
                return EventDescriptorCollection.Empty;
            }

            EventDescriptorCollection ICustomTypeDescriptor.GetEvents()
            {
                return EventDescriptorCollection.Empty;
            }

            PropertyDescriptorCollection ICustomTypeDescriptor.GetProperties(Attribute[] attributes)
            {
                return ((ICustomTypeDescriptor)this).GetProperties();
            }

            PropertyDescriptorCollection ICustomTypeDescriptor.GetProperties()
            {
                // Get the name and type for each column name
                var properties = from columnName in Columns
                                 let columnIndex = Record.GetOrdinal(columnName)
                                 let type = Record.GetFieldType(columnIndex)
                                 select new DynamicPropertyDescriptor(columnName, type);

                return new PropertyDescriptorCollection(properties.ToArray(), readOnly: true);
            }

            object ICustomTypeDescriptor.GetPropertyOwner(PropertyDescriptor pd)
            {
                return this;
            }

            private class DynamicPropertyDescriptor : PropertyDescriptor
            {
                private static readonly Attribute[] _Empty = new Attribute[0];
                private readonly Type _Type;

                public DynamicPropertyDescriptor(string name, Type type)
                    : base(name, _Empty)
                {
                    _Type = type;
                }

                public override Type ComponentType
                {
                    get { return typeof(DynamicRecord); }
                }

                public override bool IsReadOnly
                {
                    get { return true; }
                }

                public override Type PropertyType
                {
                    get { return _Type; }
                }

                public override bool CanResetValue(object component)
                {
                    return false;
                }

                /// <summary>
                /// When overridden in a derived class, gets the current value of the property on a component.
                /// </summary>
                /// <returns>
                /// The value of a property for a given component.
                /// </returns>
                /// <param name="component">The component with the property for which to retrieve the value. </param>
                public override object GetValue(object component)
                {
                    var record = component as DynamicRecord;
                    // REVIEW: Should we throw if the wrong object was passed in?
                    if (record != null)
                    {
                        return record[Name];
                    }
                    return null;
                }

                public override void ResetValue(object component)
                {
                    throw new InvalidOperationException(
                        String.Format(CultureInfo.CurrentCulture,
                                      "Record {0} Is ReadOnly", Name));
                }

                public override void SetValue(object component, object value)
                {
                    throw new InvalidOperationException(
                        String.Format(CultureInfo.CurrentCulture,
                                      "Record {0} Is ReadOnly", Name));
                }

                public override bool ShouldSerializeValue(object component)
                {
                    return false;
                }
            }
        }

        private readonly Func<DbConnection> _ConnectionFactory;
        private DbConnection _Connection;

        private Database(Func<DbConnection> connectionFactory)
        {
            _ConnectionFactory = connectionFactory;
        }

        public DbConnection Connection
        {
            get
            {
                if (_Connection == null)
                {
                    _Connection = _ConnectionFactory();
                }
                return _Connection;
            }
        }

        public void Close()
        {
            Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_Connection != null)
                {
                    _Connection.Close();
                    _Connection = null;
                }
            }
        }

        public dynamic QuerySingle(string commandText, params object[] args)
        {
            if (String.IsNullOrEmpty(commandText))
            {
                throw new ArgumentNullException("commandText");
            }

            return QueryInternal(commandText, args).FirstOrDefault();
        }

        public IEnumerable<dynamic> Query(string commandText, params object[] parameters)
        {
            if (String.IsNullOrEmpty(commandText))
            {
                throw new ArgumentNullException("commandText");
            }
            // Return a readonly collection
            return QueryInternal(commandText, parameters).ToList().AsReadOnly();
        }

        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Users are responsible for ensuring the inputs to this method are SQL Injection sanitized")]
        private IEnumerable<dynamic> QueryInternal(string commandText, params object[] parameters)
        {
            EnsureConnectionOpen();

            DbCommand command = Connection.CreateCommand();
            command.CommandText = commandText;

            AddParameters(command, parameters);
            using (command)
            {
                IEnumerable<string> columnNames = null;
                using (DbDataReader reader = command.ExecuteReader())
                {
                    foreach (DbDataRecord record in reader)
                    {
                        if (columnNames == null)
                        {
                            columnNames = GetColumnNames(record);
                        }
                        yield return new DynamicRecord(columnNames, record);
                    }
                }
            }
        }

        private static IEnumerable<string> GetColumnNames(DbDataRecord record)
        {
            // Get all of the column names for this query
            for (int i = 0; i < record.FieldCount; i++)
            {
                yield return record.GetName(i);
            }
        }

        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Users are responsible for ensuring the inputs to this method are SQL Injection sanitized")]
        public int Execute(string commandText, params object[] args)
        {
            if (String.IsNullOrEmpty(commandText))
            {
                throw new ArgumentNullException("commandText");
            }

            EnsureConnectionOpen();

            DbCommand command = Connection.CreateCommand();
            command.CommandText = commandText;

            AddParameters(command, args);
            using (command)
            {
                return command.ExecuteNonQuery();
            }
        }

        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = "This makes a database request")]
        public dynamic GetLastInsertId()
        {
            // This method only support sql ce and sql server for now
            return QueryValue("SELECT @@Identity");
        }

        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Users are responsible for ensuring the inputs to this method are SQL Injection sanitized")]
        public dynamic QueryValue(string commandText, params object[] args)
        {
            if (String.IsNullOrEmpty(commandText))
            {
                throw new ArgumentNullException("commandText");
            }

            EnsureConnectionOpen();

            DbCommand command = Connection.CreateCommand();
            command.CommandText = commandText;

            AddParameters(command, args);
            using (command)
            {
                return command.ExecuteScalar();
            }
        }

        private void EnsureConnectionOpen()
        {
            // If the connection isn't open then open it
            if (Connection.State != ConnectionState.Open)
            {
                Connection.Open();

                // Raise the connection opened event
                //OnConnectionOpened();
            }
        }

        private static void AddParameters(DbCommand command, object[] args)
        {
            if (args == null)
            {
                return;
            }

            // Create numbered parameters
            IEnumerable<DbParameter> parameters = args.Select((o, index) =>
                {
                    var parameter = command.CreateParameter();
                    parameter.ParameterName = index.ToString(CultureInfo.InvariantCulture);
                    parameter.Value = o ?? DBNull.Value;
                    return parameter;
                });

            foreach (var p in parameters)
            {
                command.Parameters.Add(p);
            }
        }

        public static Database OpenConnectionString(string connectionString)
        {
            return OpenConnectionString(connectionString, providerName: null);
        }

        public static Database OpenConnectionString(string connectionString, string providerName)
        {
            if (String.IsNullOrEmpty(connectionString))
            {
                throw new ArgumentNullException("connectionString");
            }

            return OpenConnectionStringInternal(providerName, connectionString);
        }

        public static Database Open(string name)
        {
            if (String.IsNullOrEmpty(name))
            {
                throw new ArgumentNullException("name");
            }
            return OpenNamedConnection(name);
        }

        
        private static Database OpenConnectionStringInternal(string providerName, string connectionString)
        {
            return OpenConnectionStringInternal(DbProviderFactories.GetFactory(providerName), connectionString);
        }

        private static Database OpenConnectionInternal(ConnectionStringSettings connectionConfig)
        {
            return OpenConnectionStringInternal(connectionConfig.ProviderName, connectionConfig.ConnectionString);
        }

        internal static Database OpenConnectionStringInternal(DbProviderFactory providerFactory, string connectionString)
        {
            return new Database(
                () =>
                    {
                        var conn = providerFactory.CreateConnection();
                        Debug.Assert(conn != null, "connection");
                        conn.ConnectionString = connectionString;
                        return conn;
                    });
        }

        internal static Database OpenNamedConnection(string name)
        {
            // Opens a connection using the connection string setting with the specified name
            var configuration = ConfigurationManager.ConnectionStrings[name];
            if (configuration != null)
            {
                // We've found one in the connection string setting in config so use it
                return OpenConnectionInternal(configuration);
            }

            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                                                              "ConnectionString {0} Is Not Found", name));
        }

        //private static string GetDefaultProviderName()
        //{
        //    var providerName = ConfigurationManager.AppSettings[DefaultDataProviderAppSetting];
        //    // Get the default provider name from config if there is any
        //    if (!string.IsNullOrEmpty(providerName))
        //    {
        //        providerName = SqlCeProviderName;
        //    }

        //    return providerName;
        //}

        public static bool CheckTableExists(Database db, string tableName)
        {
            var query = db.QuerySingle(@"SELECT * from INFORMATION_SCHEMA.TABLES where TABLE_NAME = @0", tableName);
            return query != null;
        }
    }
}
