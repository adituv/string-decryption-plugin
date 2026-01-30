#include "MyToolboxPlugin.h"

DLLAPI ToolboxPlugin* ToolboxPluginInstance()
{
    static MyToolboxPlugin instance;
    return &instance;
}

void MyToolboxPlugin::Initialize(ImGuiContext* ctx, ImGuiAllocFns fns, HMODULE toolbox_dll)
{
    ToolboxPlugin::Initialize(ctx, fns, toolbox_dll);
}
