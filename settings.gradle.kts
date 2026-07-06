pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "andvari"

include(":core")
include(":server")
include(":tools:vector-gen")
include(":tools:recovery-cli")
// (:app-android and :app-desktop join at P2/P3)
