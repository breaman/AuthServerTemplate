To install this template, clone the repo and then from a command prompt type
```
dotnet new -i <parentDirectoryProjectWasClonedTo>\AuthServerTemplate
```

To generate a new project based on the template, from a command prompt type
```
dotnet new breamanAuthServer -n <projectName>
```

To uninstall this template, open a command prompt and type
```
dotnet new -u <parentDirectoryProjectWasClonedTo>\AuthServerTemplate
```

After creating project, make sure to navigate into the src\&lt;projectName&gt;.Web project and run
```
dotnet restore - to get the nuget packages pulled in correctly
yarn (or npm install) - to get the node_modules installed
gulp (gulp must be installed globally with npm install -g gulp) - this will run the default task to copy the bootstrap and jquery files into the wwwroot directory
```

After doing the above, you should be able to run the application and get a basic Identity Server up and running. If run via VSCode, it will run the application on port 5005 and using Google Chrome in the incognito mode.

Project is setup to use Sqlite out of the box, to generate your initial database, use standard migration commands (the following commands would create the initial migrations, but these are already created for you)
```
dotnet ef migrations add InitialDb -c ApplicationDbContext -p ..\<projectName>.domain\<projectName>.domain.csproj
dotnet ef migrations add InitialIdentityServerPersistedGrantDbMigration -c PersistedGrantDbContext -o Data/Migrations/IdentityServer/PersistedGrantDb
dotnet ef migrations add InitialIdentityServerConfigurationDbMigration -c ConfigurationDbContext -o Data/Migrations/IdentityServer/ConfigurationDb
```

In order to create the database with the proper configuration tables added, run the following commands
```
dotnet ef database update -c ApplicationDbContext
dotnet ef database update -c PersistedGrantDbContext
dotnet ef database update -c ConfigurationDbContext
```