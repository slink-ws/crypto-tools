rm release.properties 2>/dev/null
rm pom.xml.releaseBackup 2>/dev/null
mvn release:prepare release:perform
