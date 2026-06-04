plugins {
    java
    id("com.gradleup.shadow") version "9.4.2"
}

group = "sessionguard"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.release.set(17)
}

tasks.shadowJar {
    archiveBaseName.set("session-guard")
    archiveClassifier.set("")
    archiveVersion.set("1.0.0")
}

tasks.jar {
    manifest {
        attributes["Implementation-Title"] = "Session Guard"
        attributes["Implementation-Version"] = version
    }
}
