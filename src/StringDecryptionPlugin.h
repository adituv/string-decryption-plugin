#pragma once

#include <ToolboxPlugin.h>

class StringDecryptionPlugin : public ToolboxPlugin {
public:
    StringDecryptionPlugin();
    [[nodiscard]] const char* Name() const override { return "String Decryption"; }

    void Initialize(ImGuiContext*, ImGuiAllocFns, HMODULE) override;
    void SignalTerminate() override;
    bool CanTerminate() override;
    void Terminate() override;
    
private:
    std::ofstream out_file;
    
};
