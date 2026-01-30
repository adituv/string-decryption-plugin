#pragma once

#include <ToolboxPlugin.h>

class MyToolboxPlugin : public ToolboxPlugin {
public:
    [[nodiscard]] const char* Name() const override { return "My Toolbox Plugin"; }

    void Initialize(ImGuiContext*, ImGuiAllocFns, HMODULE) override;
};
