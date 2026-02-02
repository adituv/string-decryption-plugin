include_guard()
include(FetchContent)

FetchContent_Declare(
  plugin_utils
  GIT_REPOSITORY https://github.com/adituv/ToolboxPluginUtils
  GIT_TAG master
)

FetchContent_MakeAvailable(plugin_utils)
