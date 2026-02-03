#include "StringDecryptionPlugin.h"

#include <ctre.hpp>
#include <MinHook.h>
#include <Path.h>
#include <PluginUtils/PluginUtils.h>

#include <atomic>
#include <fstream>
#include <print>

using namespace PluginUtils;

namespace
{
    std::atomic<int> in_hook_count = 0;

    std::map<std::uint32_t, std::uint64_t> logged_security_fields;

    using GetSecurityFieldFunc =
        wchar_t* (__cdecl *)(wchar_t* data, wchar_t* term, uint32_t string_id, uint64_t* out_security);
    GetSecurityFieldFunc get_security_field_func = nullptr;
    GetSecurityFieldFunc get_security_field_ret = nullptr;

    wchar_t* __cdecl on_get_security_field(wchar_t* data, wchar_t* term, uint32_t string_id, uint64_t* out_security)
    {
        ++in_hook_count;

        wchar_t* result = get_security_field_ret(data, term, string_id, out_security);

        if (out_security != nullptr && *out_security != 0)
        {
            logged_security_fields.insert_or_assign(string_id, *out_security);
        }

        --in_hook_count;
        return result;        
    }
    
    void load_from_file(const std::filesystem::path& data_file_path)
    {
        static constexpr ctll::fixed_string line_regex("^\"([0-9a-fA-F]+)\",\"([0-9a-fA-F]+)\"$");

        std::wifstream data_file(data_file_path);
        
        if (!data_file.good())
        {
            Logging::Error(L"Failed to load decrypted string data");
            return;
        }
        
        std::wstring line;
        // Skip CSV header
        std::getline(data_file, line);

        while (std::getline(data_file, line)) {
            if (auto [whole, string_id_view, security_view] = ctre::match<line_regex>(line); whole)
            {
                uint32_t string_id = std::stoul(string_id_view.to_string(), nullptr, 16);
                uint64_t security = std::stoull(security_view.to_string(), nullptr, 16);

                logged_security_fields.insert_or_assign(string_id, security);
            }
            else if (!line.empty()) {
                Logging::Warning(std::format(L"Failed to parse data file line \"{}\"", line));
            }
        }
    }

    void write_to_file(const std::filesystem::path& data_file_path)
    {
        std::ofstream data_file(data_file_path, std::ofstream::trunc);

        if (!data_file.good())
        {
            PluginUtils::GameChat::WriteMessage(L"Failed to save decrypted string data", PluginUtils::GameChat::COLOR_ERROR);
            return;
        }
        
        // Load from file first so that multiple clients can merge data together
        load_from_file(data_file_path);
        
        std::println(data_file, "string id,security");

        for (const auto& entry : logged_security_fields)
        {
            std::println(data_file, "\"{:x}\",\"{:x}\"", entry.first, entry.second);
        }

        data_file.flush();
    }
}

DLLAPI ToolboxPlugin* ToolboxPluginInstance()
{
    static StringDecryptionPlugin instance;
    return &instance;
}

StringDecryptionPlugin::StringDecryptionPlugin()
{
    std::filesystem::path plugin_output_path = Environment::GetToolboxSettingsPath() / "plugin_output";
    PathCreateDirectorySafe(plugin_output_path);
    data_file_path = plugin_output_path / "string_decryption.csv";
}

void StringDecryptionPlugin::Initialize(ImGuiContext* ctx, ImGuiAllocFns fns, HMODULE toolbox_dll)
{
    ToolboxPlugin::Initialize(ctx, fns, toolbox_dll);

    GameChat::SetPrefix(L"StringDecrypt");
    Logging::ConfigureChatLogging(Logging::LEVEL_WARNING);
#if _DEBUG
    Logging::ConfigureStdioLogging(Logging::LEVEL_DEBUG);
#else
    Logging::ConfigureStdioLogging(Logging::LEVEL_INFO);
#endif
    Logging::ConfigureFileLogging(
        Environment::GetToolboxSettingsPath() / "plugin_output" / "string_decryption.log",
        Logging::LEVEL_INFO
        );
    
    constexpr char sigga_pattern[] =
        "55 8B EC 53 56 57 E8 ? ? ? ? 8B 70 18 83 7E 20 00 74 ? 6A 22 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 83 7E 24 00 74 "
        "? 6A 23 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 8B 7D 08 85 FF 75 ? 6A 24 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 8B 5D 0C "
        "85 DB 75 ? 6A 25 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? FF 75 14";

    get_security_field_func = reinterpret_cast<GetSecurityFieldFunc>(SiggaScan(sigga_pattern));
    
    if (get_security_field_func == nullptr)
    {
        Logging::Error(L"Scan for get_security_field failed");
    }
    
    // Using MinHook directly so logging works even while TB is disabled
    if (MH_Initialize() == MH_OK)
    {
        MH_CreateHook(get_security_field_func, on_get_security_field, reinterpret_cast<void**>(&get_security_field_ret));
        MH_EnableHook(get_security_field_func);
    }
    else
    {
        Logging::Error(L"Failed to initialize MinHook");
    }

    load_from_file(this->data_file_path);
}

void StringDecryptionPlugin::SignalTerminate()
{
    MH_DisableHook(get_security_field_func);
    write_to_file(this->data_file_path);
    ToolboxPlugin::SignalTerminate();
}

bool StringDecryptionPlugin::CanTerminate()
{
    return in_hook_count.load() == 0;
}

void StringDecryptionPlugin::Terminate()
{
    MH_RemoveHook(get_security_field_func);
    MH_Uninitialize();
    ToolboxPlugin::Terminate();
}

void StringDecryptionPlugin::DrawSettings()
{
    ImGui::Text("Cached strings: %d", logged_security_fields.size());
    if (ImGui::Button("Save now"))
    {
        write_to_file(this->data_file_path);
    }
}
