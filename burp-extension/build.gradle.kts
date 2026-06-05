plugins {
    id("java")
}

group = "agent.burp"
version = "1.4.3"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.10")
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("org.java-websocket:Java-WebSocket:1.5.6")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    manifest {
        attributes["Implementation-Title"] = "agent-burp Burp Extension"
        attributes["Implementation-Version"] = version
    }
}

tasks.test {
    useJUnitPlatform()
}
