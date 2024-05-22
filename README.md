# goblin-maven-plugin

Maven plugin for Goblin.

## Installation

Build the project and install the plugin to your local maven repository:

```bash
mvn clean install
```

## Usage

To run the plugin for some project, add the following configuration in the `pom.xml` of this project:

```xml
    <properties>
        <goblin-maven-plugin.version>1.0-SNAPSHOT</goblin-maven-plugin.version>
    </properties>
    ...
    <reporting>
        <plugins>
            <plugin>
                <groupId>com.cifre.sap.su</groupId>
                <artifactId>goblin-maven-plugin</artifactId>
                <version>${goblin-maven-plugin.version}</version>
            </plugin>
        </plugins>
    </reporting>
```

Then, run the following command:

```bash
mvn site
```

This will build the project (if not already done) and generate a report in `target/site`, the Goblin report will be available there in the `Project Reports` section.
