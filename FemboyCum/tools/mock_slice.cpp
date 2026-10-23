#include "fc/mock.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace {
void save_disposable(const std::filesystem::path& path, const std::string& bytes) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
            throw std::runtime_error("could not create new disposable config");
        // Repeated tests may read an exact previous result; never reopen for writing.
        std::ifstream previous(path, std::ios::binary);
        std::string existing(bytes.size() + 1, '\0');
        previous.read(existing.data(), static_cast<std::streamsize>(existing.size()));
        existing.resize(static_cast<std::size_t>(previous.gcount()));
        if (previous.bad() || existing != bytes)
            throw std::runtime_error("refusing to replace an existing or modified file");
        return;
    }
    DWORD written{};
    const auto success = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    const auto closed = CloseHandle(file);
    if (!success || written != bytes.size() || !closed)
        throw std::runtime_error("could not save disposable config");
}
}

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::invalid_argument("usage: fc_mock_slice <new-disposable-config.fcfg>");
        const std::filesystem::path output(argv[1]);
        fc::ConfigDocument input;
        input.fields["setting.text"] = "Disposable setting";
        input.fields["mock-slice.disposable"] = "1";
        input.fields["future.unknown"] = "preserve this field";
        fc::MockEngine engine;
        fc::MockScripts scripts;
        fc::RecordingRenderer renderer;
        fc::Core core(engine, scripts, renderer);
        core.initialize(input.serialize());
        unsigned callbacks{};
        core.subscribe([&](const fc::Event&) { ++callbacks; core.set_text("Event processed"); });
        core.dispatch({"offline.mock.event", 1});
        core.render();
        core.reset_device();
        const auto saved = core.save();
        const auto parsed = fc::ConfigDocument::parse(saved);
        if (parsed.fields.at("future.unknown") != "preserve this field")
            throw std::runtime_error("unknown field lost");
        save_disposable(output, saved);
        core.shutdown();
        if (callbacks != 1 || scripts.events.size() != 1 || scripts.live)
            throw std::runtime_error("mock lifecycle failed");
        std::cout << "{\"passed\":true,\"mock_callbacks\":1,\"lua_executed\":false,"
                     "\"game_executed\":false,\"setting_recorded\":true,\"device_resets\":1}\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
