#pragma once
#include <span>
#include <vector>
#include <string>
#include <ranges>
#include <expected>
#include <algorithm>
#include <windows.h>

namespace sigz {
    constexpr inline std::int16_t WILDCARD = -1;
    constexpr inline std::size_t NO_LIMIT = 0;

    enum SIG_FORMAT {
        ida,    // "0A ? ? CD 69 69 AB"
        x64dbg, // "0A ?? ?? CD 69 69 AB"
        string,
        value
    };

    enum RET_TYPE {
        vec, // std::vector<void*>
        ptr  // void*
    };

    enum class ERROR_CODE {
        WINAPI_FAIL,
        MODULE_NOT_FOUND,
        BAD_SIGNATURE,
    };

    // INTERNAL FUNCTIONS

    [[nodiscard]] inline bool _Verify_Signature(
        const std::vector<std::int16_t>& _Signature
    ) {
        return !_Signature.empty() && std::ranges::all_of(_Signature, [](auto e) { return (e <= 0xff && e >= 0x00) || e == WILDCARD; });
    }

    [[nodiscard]] inline std::vector<void*> _Scan_Unchecked(
        std::uint8_t* _First,
        std::uint8_t* _Last,
        const std::vector<std::int16_t>& _Pattern,
        std::size_t _Limit
    ) {
        std::vector<void*> _Results{};
        for (std::uint8_t* _Ptr = _First; _Ptr < _Last - _Pattern.size(); ++_Ptr) {
            bool _Found = true;
            for (std::size_t i = 0; i < _Pattern.size(); ++i) {
                if (_Pattern[i] == WILDCARD || _Ptr[i] == _Pattern[i]) {
                    continue;
                }
                _Found = false;
                break;
            }
            if (_Found) {
                _Results.push_back(reinterpret_cast<void*>(_Ptr));
                if (_Limit != NO_LIMIT && _Results.size() == _Limit) {
                    break;
                }
            }
        }
        return _Results;
    }

    // HELPER FUNCTIONS

    template <SIG_FORMAT>
    struct _Make_Sig_Fn;

    template <>
    struct _Make_Sig_Fn<ida> {
        [[nodiscard]] std::vector<std::int16_t> operator()(
            std::string_view _Pattern
            ) const {
            std::vector<std::int16_t> _Result{};
            for (auto&& _Token : std::ranges::split_view(_Pattern, ' ') | std::views::transform([](auto e) { return std::string_view(e); })) {
                _Result.push_back(_Token == "?" ? WILDCARD : static_cast<std::int16_t>(std::stoi(_Token.data(), nullptr, 16)));
            }
            while (!_Result.empty() && _Result.back() == WILDCARD) {
                _Result.pop_back();
            }
            return _Result;
        }
    };

    template <>
    struct _Make_Sig_Fn<x64dbg> {
        [[nodiscard]] std::vector<std::int16_t> operator()(
            std::string_view _Pattern
            ) const {
            std::vector<std::int16_t> _Result{};
            for (auto&& _Token : std::ranges::split_view(_Pattern, ' ') | std::views::transform([](auto e) { return std::string_view(e); })) {
                _Result.push_back(_Token == "??" ? WILDCARD : static_cast<std::int16_t>(std::stoi(_Token.data(), nullptr, 16)));
            }
            while (!_Result.empty() && _Result.back() == WILDCARD) {
                _Result.pop_back();
            }
            return _Result;
        }
    };

    template <>
    struct _Make_Sig_Fn<string> {
        [[nodiscard]] std::vector<std::int16_t> operator()(
            std::string_view _String,
            bool _Null = true
            ) const {
            return std::vector<std::int16_t>(_String.begin(), _Null ? _String.end() + 1 : _String.end());
        }

        [[nodiscard]] std::vector<std::int16_t> operator()(
            std::wstring_view _String,
            bool _Null = true
            ) const {
            auto _First = reinterpret_cast<const std::int8_t*>(_String.data());
            auto _Last = reinterpret_cast<const std::int8_t*>(_String.data()) + _String.length();
            return std::vector<std::int16_t>(_First, _Null ? _Last + 1 : _Last);
        }
    };

    template <>
    struct _Make_Sig_Fn<value> {
        template <class _Ty>
        [[nodiscard]] std::vector<std::int16_t> operator()(
            const _Ty& _Value
            ) const {
            return std::vector<std::int16_t>(reinterpret_cast<const std::int8_t*>(&_Value), reinterpret_cast<const std::int8_t*>(&_Value) + sizeof(_Ty));
        }
    };

    template <SIG_FORMAT _Format>
    constexpr inline _Make_Sig_Fn<_Format> make_sig;

    [[nodiscard]] constexpr inline std::string_view to_string(
        ERROR_CODE _Err
    ) {
        using enum ERROR_CODE;
        switch (_Err) {
        case WINAPI_FAIL: return "WINAPI_FAIL";
        case MODULE_NOT_FOUND: return "MODULE_NOT_FOUND";
        case BAD_SIGNATURE: return "BAD_SIGNATURE";
        default: return "UNKNOWN";
        };
    }

    // NORMAL SCAN

    template <RET_TYPE>
    struct _Scan_Fn;

    template <>
    struct _Scan_Fn<vec> {
        [[nodiscard]] std::expected<std::vector<void*>, ERROR_CODE> operator()(
            std::uint8_t* _First,
            std::uint8_t* _Last,
            const std::vector<std::int16_t>& _Signature,
            std::size_t _Limit = NO_LIMIT
            ) const {
            if (!_Verify_Signature(_Signature)) {
                return std::unexpected(ERROR_CODE::BAD_SIGNATURE);
            }

            std::vector<MEMORY_BASIC_INFORMATION> _Regions{};
            MEMORY_BASIC_INFORMATION _Mem_Info{};

            for (std::uint8_t* _Ptr = _First; _Ptr < _Last; ++_Ptr) {
                if (!VirtualQuery(_Ptr, &_Mem_Info, sizeof(_Mem_Info))) {
                    return std::unexpected(ERROR_CODE::WINAPI_FAIL);
                }

                _Regions.push_back(_Mem_Info);
                _Ptr += _Mem_Info.RegionSize;
            }

            std::size_t _Original_Limit = _Limit;
            std::vector<void*> _Results{};

            for (auto& _Region : _Regions) {
                if ((_Region.State & (MEM_COMMIT | MEM_RESERVE)) == 0 || _Region.Protect == 0 || (_Region.Protect & 0xf6) == 0 || (_Region.Protect & 0x40000301) != 0) {
                    continue;
                }

                auto _Region_First = reinterpret_cast<std::uint8_t*>(_Region.BaseAddress);
                auto _Region_Last = reinterpret_cast<std::uint8_t*>(_Region.BaseAddress) + _Region.RegionSize;

                auto _Region_Results = _Scan_Unchecked(max(_First, _Region_First), min(_Last, _Region_Last), _Signature, _Limit);

                for (auto _Ptr : _Region_Results) {
                    _Results.push_back(_Ptr);
                }

                if (_Region_Results.size() != _Limit) {
                    _Limit -= _Region_Results.size();
                }

                if (_Original_Limit != NO_LIMIT && _Limit == 0) {
                    break;
                }
            }

            return _Results;
        }
    };

    template <>
    struct _Scan_Fn<ptr> {
        [[nodiscard]] std::expected<void*, ERROR_CODE> operator()(
            std::uint8_t* _First,
            std::uint8_t* _Last,
            const std::vector<std::int16_t>& _Signature
            ) const {
            auto _Result = _Scan_Fn<vec>{}(_First, _Last, _Signature, 1);
            if (!_Result.has_value()) {
                return std::unexpected(_Result.error());
            }
            else {
                return _Result->empty() ? nullptr : _Result->front();
            }
        }
    };

    template <RET_TYPE _Type = vec>
    constexpr inline _Scan_Fn<_Type> scan;
    constexpr inline _Scan_Fn<ptr> scan_first;

    // IMAGE SCAN

    template <RET_TYPE>
    struct _Scan_Img_Fn;

    template <>
    struct _Scan_Img_Fn<vec> {
        [[nodiscard]] std::expected<std::vector<void*>, ERROR_CODE> operator()(
            std::string_view _Module,
            const std::vector<std::int16_t>& _Signature,
            std::size_t _Limit = NO_LIMIT
            ) const {
            if (!_Verify_Signature(_Signature)) {
                return std::unexpected(ERROR_CODE::BAD_SIGNATURE);
            }

            std::uint8_t* _Base = reinterpret_cast<std::uint8_t*>(GetModuleHandleA(_Module.data()));
            if (!_Base) {
                return std::unexpected(ERROR_CODE::MODULE_NOT_FOUND);
            }

            IMAGE_DOS_HEADER* _Dos_Header = reinterpret_cast<IMAGE_DOS_HEADER*>(_Base);
            IMAGE_NT_HEADERS* _Nt_Headers = reinterpret_cast<IMAGE_NT_HEADERS*>(_Base + _Dos_Header->e_lfanew);

            return _Scan_Unchecked(_Base, _Base + _Nt_Headers->OptionalHeader.SizeOfImage, _Signature, _Limit);
        }
    };

    template <>
    struct _Scan_Img_Fn<ptr> {
        [[nodiscard]] std::expected<void*, ERROR_CODE> operator()(
            std::string_view _Module,
            const std::vector<std::int16_t>& _Signature
            ) const {
            auto _Result = _Scan_Img_Fn<vec>{}(_Module, _Signature, 1);
            if (!_Result.has_value()) {
                return std::unexpected(_Result.error());
            }
            else {
                return _Result->empty() ? nullptr : _Result->front();
            }
        }
    };

    template <RET_TYPE _Type = vec>
    constexpr inline _Scan_Img_Fn<_Type> scan_image;
    constexpr inline _Scan_Img_Fn<ptr> scan_image_first;
}
