ExternalProject_Add(pdargs
    GIT_REPOSITORY https://github.com/sskcvqikf/pdargs.git
    GIT_TAG origin/main
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    PREFIX ${EXTERNAL_INSTALL_LOCATION}
    )

set(PDARGS_INCLUDE_DIR ${EXTERNAL_INSTALL_LOCATION}/src/pdargs/include)
