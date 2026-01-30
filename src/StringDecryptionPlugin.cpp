#include "StringDecryptionPlugin.h"

#include <atomic>
#include <fstream>
#include <print>

#include <ctre.hpp>
#include <GWCA/Utilities/Hooker.h>
#include <GWCA/Utilities/Scanner.h>
#include <Path.h>

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
        
        if (out_security != nullptr)
        {
            logged_security_fields.insert_or_assign(string_id, *out_security);
        }
        
        --in_hook_count;
        return result;        
    }
    
    std::pair<std::string, std::string> process_sigga_pattern(std::string_view sigga_pattern)
    {
        static constexpr ctll::fixed_string byte_regex = "[0-9a-fA-F]{2}";
        static constexpr ctll::fixed_string wild_regex = "\\?+";
        
        std::string pattern;
        std::string mask;
        
        for (const auto byte : std::ranges::split_view(sigga_pattern, ' '))
        {
            if (ctre::match<byte_regex>(byte))
            {
                unsigned int byte_value = std::stoi(std::string(byte.begin(), byte.end()), nullptr, 16);
                pattern.push_back(byte_value);
                mask.push_back('x');
            }
            else if (ctre::match<wild_regex>(byte))
            {
                pattern.push_back('\0');
                mask.push_back('?');
            }
            else
            {
                throw std::invalid_argument("Invalid sigga pattern");
            }
        }
        
        return std::make_pair(pattern, mask);
    }
    
    std::filesystem::path get_output_folder_path()
    {
        std::filesystem::path computer_name;
        if (!PathGetComputerName(computer_name))
        {
            return "";
        }
        
        std::filesystem::path docpath;
        if (!PathGetDocumentsPath(docpath, L"GWToolboxpp"))
        {
            return "";
        }
        docpath = docpath / computer_name / "plugin_output";
        
        if (!PathCreateDirectorySafe(docpath))
        {
            return "";
        }
        
        return docpath;
    }
}

DLLAPI ToolboxPlugin* ToolboxPluginInstance()
{
    static StringDecryptionPlugin instance;
    return &instance;
}

StringDecryptionPlugin::StringDecryptionPlugin()
{
    data_file_path = get_output_folder_path() / "string_decryption.csv";
}

void StringDecryptionPlugin::Initialize(ImGuiContext* ctx, ImGuiAllocFns fns, HMODULE toolbox_dll)
{
    ToolboxPlugin::Initialize(ctx, fns, toolbox_dll);
    
    constexpr char sigga_pattern[] =
        "55 8B EC 53 56 57 E8 ? ? ? ? 8B 70 18 83 7E 20 00 74 ? 6A 22 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 83 7E 24 00 74 "
        "? 6A 23 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 8B 7D 08 85 FF 75 ? 6A 24 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 8B 5D 0C "
        "85 DB 75 ? 6A 25 BA ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? FF 75 14";
    
    std::pair<std::string, std::string> tmp = process_sigga_pattern(sigga_pattern);
    const char* pattern = tmp.first.c_str();
    const char* mask = tmp.second.c_str();
    
    get_security_field_func = reinterpret_cast<GetSecurityFieldFunc>(GW::Scanner::Find(pattern, mask, 0)); // NOLINT(performance-no-int-to-ptr)
    GW::Hook::CreateHook(reinterpret_cast<void**>(&get_security_field_func),on_get_security_field,
                         reinterpret_cast<void**>(&get_security_field_ret));
    GW::Hook::EnableHooks(get_security_field_func);

    std::ifstream data_file(data_file_path);
    std::string line;
    // Skip CSV header
    std::getline(data_file, line);

    while (std::getline(data_file, line)) {
        size_t comma_pos = line.find(',');
        if (comma_pos == std::string::npos)
        {
            // Invalid data; stop loading
            break;
        }

        uint32_t string_id = std::stoi(line.substr(0, comma_pos), nullptr, 16);
        uint64_t security = std::stoll(line.substr(comma_pos + 1), nullptr, 16);

        logged_security_fields.insert_or_assign(string_id, security);
    }
}

void StringDecryptionPlugin::SignalTerminate()
{
    GW::Hook::DisableHooks(get_security_field_func);

    this->WriteToFile();
    
    ToolboxPlugin::SignalTerminate();
}

bool StringDecryptionPlugin::CanTerminate()
{
    return in_hook_count.load() == 0;
}

void StringDecryptionPlugin::Terminate()
{
    GW::Hook::RemoveHook(get_security_field_func);
    ToolboxPlugin::Terminate();
}

void StringDecryptionPlugin::DrawSettings()
{
    ImGui::Text("Cached strings: %d", logged_security_fields.size());
    if (ImGui::Button("Save now"))
    {
        this->WriteToFile();
    }
}

void StringDecryptionPlugin::WriteToFile() const
{
    std::ofstream data_file(this->data_file_path, std::ofstream::trunc);

    // TODO: write error to chat on failing to save
    
    std::println(data_file, "string id,security");

    for (const auto& entry : logged_security_fields)
    {
        std::println(data_file, "\"{:x}\",\"{:x}\"", entry.first, entry.second);
    }

    data_file.flush();
}
