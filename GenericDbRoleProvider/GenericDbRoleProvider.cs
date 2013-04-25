using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Security;

namespace CB.Web.Security
{
    public class GenericDbRoleProvider : RoleProvider
    {
        private string SafeUserTableName
        {
            get { return "[" + UserTableName + "]"; }
        }
        private string SafeRoleTableName
        {
            get { return "[" + RoleTableName + "]"; }
        }
        private string SafeUsersInRoleTableName
        {
            get { return "[" + UsersInRoleTableName + "]"; }
        }

        private string SafeUserNameColumnOfUserTable
        {
            get { return "[" + UserNameColumnOfUserTable + "]"; }
        }

        private string SafeUserIdColumnOfUserTable
        {
            get { return "[" + UserIdColumnOfUserTable + "]"; }
        }

        private string SafeUserIdColumnOfUserInRoleTable
        {
            get { return "[" + UserIdColumnOfUserInRoleTable + "]"; }
        }

        private string SafeRoleIdColumnOfRoleTable
        {
            get { return "[" + RoleIdColumnOfRoleTable + "]"; }
        }

        private string SafeRoleIdColumnOfUserInRoleTable
        {
            get { return "[" + RoleIdColumnOfUserInRoleTable + "]"; }
        }

        private string SafeRoleNameColumnOfRoleTable
        {
            get { return "[" + RoleNameColumnOfRoleTable + "]"; }
        }

        public string UserTableName { get; set; }
        public string RoleTableName { get; set; }
        public string UsersInRoleTableName { get; set; }

        public string UserNameColumnOfUserTable { get; set; }

        public string UserIdColumnOfUserTable { get; set; }
        public string UserIdColumnOfUserInRoleTable { get; set; }

        public string RoleIdColumnOfRoleTable { get; set; }
        public string RoleIdColumnOfUserInRoleTable { get; set; }

        public string RoleNameColumnOfRoleTable { get; set; }

        public override string ApplicationName { get; set; }

        public string ConnectionStringName { get; private set; }

        public override void Initialize(string name, NameValueCollection config)
        {
            //
            // Initialize values from web.config.
            //
            if (config == null)
                throw new ArgumentNullException("config");

            if (string.IsNullOrEmpty(name))
            {
                name = "FRAMRoleProvider";
            }

            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "FRAM Role provider");
            }

            base.Initialize(name, config);

            RoleTableName = GetValueFromConfig(config, "roleTableName", true, "webpages_Roles");
            UsersInRoleTableName = GetValueFromConfig(config, "usersInRoleTableName", true, "webpages_UsersInRoles");
            UserTableName = GetValueFromConfig(config, "userTableName", true, "User");

            RoleIdColumnOfRoleTable = GetValueFromConfig(config, "roleIdColumnOfRoleTable", true, "Id");
            RoleIdColumnOfUserInRoleTable = GetValueFromConfig(config, "roleIdColumnOfUserInRoleTable", true, "RoleId");

            UserIdColumnOfUserTable = GetValueFromConfig(config, "userIdColumnOfUserTable", true, "Id");
            UserIdColumnOfUserInRoleTable = GetValueFromConfig(config, "userIdColumnOfUserInRoleTable", true, "UserId");

            UserNameColumnOfUserTable = GetValueFromConfig(config, "userNameColumnOfUserTable", true, "UserName");

            RoleNameColumnOfRoleTable = GetValueFromConfig(config, "roleNameColumnOfRoleTable", true, "RoleName");

            ConnectionStringName = GetValueFromConfig(config, "connectionStringName", false, null);
        }

        private string GetValueFromConfig(NameValueCollection config, string key, bool allowEmpty, string defaultResult)
        {
            if (config[key] == null || string.IsNullOrEmpty(config[key].Trim()))
            {
                if (!allowEmpty)
                {
                    throw new ProviderException(key + " cannot be empty.");
                }
                return defaultResult;
            }
            else
            {
                return config[key];
            }
        }

        private Database ConnectToDatabase()
        {
            return Database.Open(ConnectionStringName);
        }

        private List<object> GetUserIdsFromNames(Database db, params string[] usernames)
        {
            var userIds = new List<object>(usernames.Length);
            foreach (string username in usernames)
            {
                var r = db.QuerySingle(
                    string.Format("SELECT {0} FROM {1} WHERE {2} = @0", SafeUserIdColumnOfUserTable, SafeUserTableName, SafeUserNameColumnOfUserTable), username);
                if (r == null)
                {
                    throw new InvalidOperationException("No User Found");
                }
                userIds.Add(r[0]);
            }
            return userIds;
        }

        private List<object> GetRoleIdsFromNames(Database db, string[] roleNames)
        {
            var roleIds = new List<object>(roleNames.Length);
            foreach (var role in roleNames)
            {
                var id = FindRoleId(db, role);
                if (id == null)
                {
                    throw new InvalidOperationException("No Role Found");
                }
                roleIds.Add(id);
            }
            return roleIds;
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            using (var db = ConnectToDatabase())
            {
                var userCount = usernames.Length;
                var roleCount = roleNames.Length;
                var userIds = GetUserIdsFromNames(db, usernames);
                var roleIds = GetRoleIdsFromNames(db, roleNames);

                // Generate a INSERT INTO for each userid/rowid combination, where userIds are the first params, and roleIds follow
                for (var uId = 0; uId < userCount; uId++)
                {
                    for (var rId = 0; rId < roleCount; rId++)
                    {
                        if (IsUserInRole(usernames[uId], roleNames[rId]))
                        {
                            throw new InvalidOperationException(
                                String.Format("User {0} Already In Role {1}", usernames[uId], roleNames[rId]));
                        }

                        // REVIEW: is there a way to batch up these inserts?
                        var rows =
                            db.Execute(
                                string.Format(
                                    "INSERT INTO {0} ({1},{2}) VALUES (@0,@1);", SafeUsersInRoleTableName, SafeUserIdColumnOfUserInRoleTable, SafeRoleIdColumnOfUserInRoleTable),
                                userIds[uId], roleIds[rId]);
                        if (rows != 1)
                        {
                            throw new ProviderException("DbFailure");
                        }
                    }
                }
            }

        }

        public override void CreateRole(string roleName)
        {
            using (var db = ConnectToDatabase())
            {
                var roleId = FindRoleId(db, roleName);
                if (roleId != null)
                {
                    throw new InvalidOperationException(String.Format("Role {0} Exists", roleName));
                }

                var rows = db.Execute(string.Format("INSERT INTO {0} ({1}) VALUES(@0)", SafeRoleTableName, SafeRoleNameColumnOfRoleTable), roleName);
                if (rows != 1)
                {
                    throw new ProviderException("DbFailure");
                }
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            using (var db = ConnectToDatabase())
            {
                var roleId = FindRoleId(db, roleName);
                if (roleId == null)
                {
                    return false;
                }

                if (throwOnPopulatedRole)
                {
                    if (db.Query(@"SELECT * FROM " + SafeUsersInRoleTableName + " WHERE (" + SafeRoleIdColumnOfUserInRoleTable + " = @0)", roleId).Any())
                    {
                        throw new InvalidOperationException(String.Format("Role {0} Populated", roleName));
                    }
                }
                else
                {
                    // Delete any users in this role first
                    db.Execute(@"DELETE FROM " + SafeUsersInRoleTableName + " WHERE (" + SafeRoleIdColumnOfUserInRoleTable + " = @0)", roleId);
                }

                var rows = db.Execute(@"DELETE FROM " + SafeRoleTableName + " WHERE (" + SafeRoleIdColumnOfRoleTable + " = @0)", roleId);
                return (rows == 1); // REVIEW: should this ever be > 1?
            }
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            using (var db = ConnectToDatabase())
            {
                // REVIEW: Is there any way to directly get out a string[]?
                var userNames = db.Query(
                    @"SELECT u." + SafeUserNameColumnOfUserTable +
                    " FROM " + SafeUserTableName + " u, " + UsersInRoleTableName + " ur, " + SafeRoleTableName + " r " +
                    "Where (r." + SafeRoleNameColumnOfRoleTable + " = @0 and ur." + SafeRoleIdColumnOfUserInRoleTable + " = r." + RoleIdColumnOfRoleTable + " and ur." +
                    SafeUserIdColumnOfUserInRoleTable + " = u." + SafeUserIdColumnOfUserTable + " and u." + SafeUserNameColumnOfUserTable + " LIKE @1)",
                    new object[] { roleName, usernameToMatch }).ToArray();
                var users = new string[userNames.Length];
                for (int i = 0; i < userNames.Length; i++)
                {
                    users[i] = (string)userNames[i][0];
                }
                return users;
            }
        }

        public override string[] GetAllRoles()
        {
            using (var db = ConnectToDatabase())
            {
                return db.Query(@"SELECT " + SafeRoleNameColumnOfRoleTable + " FROM " + SafeRoleTableName).Select(d => (string)d[0]).ToArray();
            }
        }

        public override string[] GetRolesForUser(string username)
        {
            using (var db = ConnectToDatabase())
            {
                var userId = GetUserIdsFromNames(db, username)[0];
                if (userId == null)
                {
                    throw new InvalidOperationException(String.Format("No User {0} Found", username));
                }

                var query = @"SELECT r." + SafeRoleNameColumnOfRoleTable + " FROM " + SafeUsersInRoleTableName + " u, " + SafeRoleTableName + " r " +
                            "Where (u." + SafeUserIdColumnOfUserInRoleTable + " = @0 and u." + SafeRoleIdColumnOfUserInRoleTable + " = r." + SafeRoleIdColumnOfRoleTable +
                            ") GROUP BY r." + SafeRoleNameColumnOfRoleTable;
                return db.Query(query, new[] { userId }).Select(d => (string)d[0]).ToArray();
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            using (var db = ConnectToDatabase())
            {
                var query = @"SELECT u." + SafeUserNameColumnOfUserTable + " FROM " + SafeUserTableName + " u, " + UsersInRoleTableName + " ur, " + SafeRoleTableName + " r " +
                            "Where (r." + SafeRoleNameColumnOfRoleTable + " = @0 and ur." + SafeRoleIdColumnOfUserInRoleTable + " = r." + SafeRoleIdColumnOfRoleTable + " and ur." +
                            SafeUserIdColumnOfUserInRoleTable + " = u." + SafeUserIdColumnOfUserTable + ")";
                return db.Query(query, new object[] { roleName }).Select(d => (string)d[0]).ToArray();
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool IsUserInRole(string username, string roleName)
        {
            using (var db = ConnectToDatabase())
            {
                var count =
                    db.QuerySingle(
                        "SELECT COUNT(*) FROM " + SafeUserTableName + " u, " + UsersInRoleTableName + " ur, " + RoleTableName + " r Where (u." + SafeUserNameColumnOfUserTable +
                        " = @0 and r." + SafeRoleNameColumnOfRoleTable + " = @1 and ur." + SafeRoleIdColumnOfUserInRoleTable + " = r." + SafeRoleIdColumnOfRoleTable + " and ur." +
                        SafeUserIdColumnOfUserInRoleTable + " = u." + SafeUserIdColumnOfUserTable + ")", username, roleName);
                return (count[0] == 1);
            }
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            foreach (var rolename in roleNames)
            {
                if (!RoleExists(rolename))
                {
                    throw new InvalidOperationException(String.Format("No Role {0} Found", rolename));
                }
            }

            foreach (var username in usernames)
            {
                foreach (var rolename in roleNames)
                {
                    if (!IsUserInRole(username, rolename))
                    {
                        throw new InvalidOperationException(String.Format("User {0} Not In Role {1}", username, rolename));
                    }
                }
            }

            using (var db = ConnectToDatabase())
            {
                var userIds = GetUserIdsFromNames(db, usernames);
                var roleIds = GetRoleIdsFromNames(db, roleNames);

                foreach (var userId in userIds)
                {
                    foreach (var roleId in roleIds)
                    {
                        // Review: Is there a way to do these all in one query?
                        var rows =
                            db.Execute(
                                "DELETE FROM " + UsersInRoleTableName + " WHERE " + SafeUserIdColumnOfUserInRoleTable + " = @0 and " + SafeRoleIdColumnOfUserInRoleTable +
                                " = @1", userId, roleId);
                        if (rows != 1)
                        {
                            throw new ProviderException("DbFailure");
                        }
                    }
                }
            }
        }

        private object FindRoleId(Database db, string roleName)
        {
            var r = db.QuerySingle(
                string.Format("SELECT {0} FROM {1} WHERE ({2} = @0)", SafeRoleIdColumnOfRoleTable, SafeRoleTableName, SafeRoleNameColumnOfRoleTable), roleName);
            if (r == null)
            {
                return null;
            }
            return r[0];
        }

        public override bool RoleExists(string roleName)
        {
            using (var db = ConnectToDatabase())
            {
                return (FindRoleId(db, roleName) != null);
            }
        }
    }
}
