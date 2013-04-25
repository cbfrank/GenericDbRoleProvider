GenericDbRoleProvider
=====================
For the default, .NET have the SqlRoleProvide which only works on Sql Server with the predesigned database schema. This is not a flexible way.
.net MVC4, a new class "SimpleRoleProvider" which can work on most database and enable user to define their database chema.
Unfortunately, this class can't be used with windows authentication, becasue it is included in the WebMatrix.WebData.dll, and in that assembly,
some function hard code to use form authentication.
So I develop this class to work in similar way that enable you custom you own database schem and work with both windows authentication and form authentication.

To use this class, add or overwrite the below section in web.config
<system.web>
    <roleManager defaultProvider="FRAMRoleProvider" enabled="true">
      <providers>
        <clear />
        <add name="YourProviderName" roleTableName="Role" usersInRoleTableName="UserInRole" userTableName="User" roleIdColumnOfRoleTable="Id" roleIdColumnOfUserInRoleTable="RoleId" userIdColumnOfUserTable="Id" userIdColumnOfUserInRoleTable="UserId" userNameColumnOfUserTable="UserName" roleNameColumnOfRoleTable="Id" connectionStringName="SomeConnectionName" type="CB.Web.Security.GenericDbRoleProvider.GenericDbRoleProvider" />
      </providers>
    </roleManager>
</system.web>

Attributes:
roleTableName:
usersInRoleTableName:
userTableName:
roleIdColumnOfRoleTable:
roleIdColumnOfUserInRoleTable:
userIdColumnOfUserTable:
userIdColumnOfUserInRoleTable:
userNameColumnOfUserTable:
roleNameColumnOfRoleTable:

To use this class:
You have create three tables: user table, role table and use in role table, in user table, you must have one column for user id, if the user id is different to the user name, then you can create a user name column in user table.
The user name is the principal.Identity.Name for windows authentication and form authenctication, for Claims based authentication, you can custom it.
then, this role provide will use the user name to find the user id, and then lookup in the user in role table with the specified user id, if the user id is found and the role id of the specified role is include for this user, then it will return true.

Project url on Nuget: https://nuget.org/packages/GenericDbRoleProvider/