#include <Python.h>
#include <windows.h>
#include <Psapi.h>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <condition_variable>
#include <queue>

// Help wanted. Crashes main server somehow. On /mop/init call. it crashes. 

// ConPTY API function pointers
typedef HRESULT (WINAPI *CreatePseudoConsoleFunc)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
typedef void (WINAPI *ClosePseudoConsoleFunc)(HPCON);
typedef BOOL (WINAPI *ResizePseudoConsoleFunc)(HPCON, COORD);

static CreatePseudoConsoleFunc pCreatePseudoConsole = nullptr;
static ClosePseudoConsoleFunc pClosePseudoConsole = nullptr;
static ResizePseudoConsoleFunc pResizePseudoConsole = nullptr;
static bool conpty_available = false;

// I/O context structure for proper overlapped I/O
struct IoContext {
    OVERLAPPED overlapped;
    char* buffer;
    DWORD buffer_size;
    bool completed;
    DWORD bytes_transferred;
    BOOL success;
};

// ConPTY Object Structure
typedef struct {
    PyObject_HEAD
    HPCON hPC;
    HANDLE hInputPipeWrite;      // Write end of input pipe (to console)
    HANDLE hOutputPipeRead;      // Read end of output pipe (from console)
    HANDLE hProcess;
    DWORD dwProcessId;
    std::atomic<bool> closed;
    CRITICAL_SECTION lock;
    // Async I/O tracking
    std::mutex io_mutex;
    std::condition_variable io_cv;
    std::queue<IoContext*> pending_reads;
    std::queue<IoContext*> pending_writes;
    std::atomic<bool> io_thread_running;
    HANDLE io_thread_handle;
} ConPTYObject;

// Forward declarations
static void initialize_conpty_api();
static bool create_environment_block(PyObject* env_dict, wchar_t** env_block_out);
static void ConPTY_dealloc(ConPTYObject* self);
static PyObject* ConPTY_new(PyTypeObject* type, PyObject* args, PyObject* kwds);
static int ConPTY_init(ConPTYObject* self, PyObject* args, PyObject* kwds);
static PyObject* ConPTY_get_pid(ConPTYObject* self, void* closure);
static PyObject* ConPTY_set_echo(ConPTYObject* self, PyObject* args);
static PyObject* ConPTY_send_signal(ConPTYObject* self, PyObject* args);
static PyObject* ConPTY_read_async(ConPTYObject* self);
static PyObject* ConPTY_write_async(ConPTYObject* self, PyObject* args);
static PyObject* ConPTY_close(ConPTYObject* self);
static DWORD WINAPI io_completion_thread(LPVOID lpParam);

// Initialize ConPTY API function pointers at runtime
static void initialize_conpty_api() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
        if (kernelbase) {
            pCreatePseudoConsole = reinterpret_cast<CreatePseudoConsoleFunc>(
                GetProcAddress(kernelbase, "CreatePseudoConsole"));
            pClosePseudoConsole = reinterpret_cast<ClosePseudoConsoleFunc>(
                GetProcAddress(kernelbase, "ClosePseudoConsole"));
            pResizePseudoConsole = reinterpret_cast<ResizePseudoConsoleFunc>(
                GetProcAddress(kernelbase, "ResizePseudoConsole"));
            conpty_available = (pCreatePseudoConsole != nullptr && pClosePseudoConsole != nullptr);
        }
    });
}

// Create environment block from Python dictionary
static bool create_environment_block(PyObject* env_dict, wchar_t** env_block_out) {
    *env_block_out = nullptr;
    
    if (!env_dict || env_dict == Py_None) {
        return true;
    }
    
    if (!PyDict_Check(env_dict)) {
        PyErr_SetString(PyExc_TypeError, "env parameter must be a dictionary");
        return false;
    }
    
    // Get current environment size estimate
    wchar_t* current_env = GetEnvironmentStringsW();
    if (!current_env) {
        PyErr_SetFromWindowsErr(GetLastError());
        return false;
    }
    
    // Count current environment variables
    size_t current_count = 0;
    wchar_t* ptr = current_env;
    while (*ptr) {
        current_count++;
        ptr += wcslen(ptr) + 1;
    }
    FreeEnvironmentStringsW(current_env);
    
    // Get number of new environment variables
    Py_ssize_t new_count = PyDict_Size(env_dict);
    if (new_count < 0) {
        return false;
    }
    
    // Create combined environment strings
    std::vector<std::wstring> env_strings;
    env_strings.reserve(current_count + new_count);
    
    // Add current environment variables
    current_env = GetEnvironmentStringsW();
    ptr = current_env;
    while (*ptr) {
        env_strings.emplace_back(ptr);
        ptr += wcslen(ptr) + 1;
    }
    FreeEnvironmentStringsW(current_env);
    
    // Add/override with new environment variables
    PyObject *key, *value;
    Py_ssize_t pos = 0;
    while (PyDict_Next(env_dict, &pos, &key, &value)) {
        PyObject* key_str = PyObject_Str(key);
        PyObject* value_str = PyObject_Str(value);
        if (!key_str || !value_str) {
            Py_XDECREF(key_str);
            Py_XDECREF(value_str);
            PyErr_SetString(PyExc_RuntimeError, "Failed to convert environment key/value to string");
            return false;
        }
        
        wchar_t* wkey = PyUnicode_AsWideCharString(key_str, nullptr);
        wchar_t* wvalue = PyUnicode_AsWideCharString(value_str, nullptr);
        Py_DECREF(key_str);
        Py_DECREF(value_str);
        
        if (!wkey || !wvalue) {
            free(wkey);
            free(wvalue);
            PyErr_SetString(PyExc_RuntimeError, "Failed to convert environment key/value to wide string");
            return false;
        }
        
        std::wstring env_entry = std::wstring(wkey) + L"=" + std::wstring(wvalue);
        free(wkey);
        free(wvalue);
        
        // Check if this environment variable already exists
        bool found = false;
        for (auto& existing : env_strings) {
            size_t equal_pos = existing.find(L'=');
            if (equal_pos != std::wstring::npos && 
                existing.substr(0, equal_pos) == std::wstring(wkey)) {
                existing = env_entry;
                found = true;
                break;
            }
        }
        
        if (!found) {
            env_strings.push_back(env_entry);
        }
    }
    
    // Calculate total size needed (including null terminators)
    size_t total_size = 0;
    for (const auto& str : env_strings) {
        total_size += str.length() + 1; // +1 for null terminator
    }
    total_size += 2; // Final double null terminator
    
    // Allocate and build environment block
    wchar_t* env_block = static_cast<wchar_t*>(malloc(total_size * sizeof(wchar_t)));
    if (!env_block) {
        PyErr_NoMemory();
        return false;
    }
    
    wchar_t* current = env_block;
    for (const auto& str : env_strings) {
        size_t len = str.length() + 1;
        memcpy(current, str.c_str(), len * sizeof(wchar_t));
        current += len;
    }
    *current = L'\0'; // Double null terminator
    
    *env_block_out = env_block;
    return true;
}

// I/O completion thread to handle async operations safely
static DWORD WINAPI io_completion_thread(LPVOID lpParam) {
    ConPTYObject* self = static_cast<ConPTYObject*>(lpParam);
    
    while (self->io_thread_running) {
        IoContext* context = nullptr;
        {
            std::unique_lock<std::mutex> lock(self->io_mutex);
            self->io_cv.wait(lock, [self]() {
                return !self->pending_reads.empty() || !self->pending_writes.empty() || !self->io_thread_running;
            });
            
            if (!self->io_thread_running) break;
            
            if (!self->pending_reads.empty()) {
                context = self->pending_reads.front();
                self->pending_reads.pop();
            } else if (!self->pending_writes.empty()) {
                context = self->pending_writes.front();
                self->pending_writes.pop();
            }
        }
        
        if (!context) continue;
        
        // Wait for I/O completion
        DWORD bytes_transferred = 0;
        BOOL success = GetOverlappedResult(
            context->overlapped.hEvent == self->hOutputPipeRead ? 
                self->hOutputPipeRead : self->hInputPipeWrite,
            &context->overlapped,
            &bytes_transferred,
            TRUE
        );
        
        context->success = success;
        context->bytes_transferred = bytes_transferred;
        context->completed = true;
        
        // Notify Python thread
        {
            std::unique_lock<std::mutex> lock(self->io_mutex);
            self->io_cv.notify_all();
        }
    }
    
    return 0;
}

// Deallocate ConPTY object
static void ConPTY_dealloc(ConPTYObject* self) {
    if (!self->closed.exchange(true)) {
        // Stop I/O thread first
        self->io_thread_running = false;
        {
            std::lock_guard<std::mutex> lock(self->io_mutex);
            self->io_cv.notify_all();
        }
        
        if (self->io_thread_handle != INVALID_HANDLE_VALUE) {
            WaitForSingleObject(self->io_thread_handle, INFINITE);
            CloseHandle(self->io_thread_handle);
            self->io_thread_handle = INVALID_HANDLE_VALUE;
        }
        
        // Clean up pending I/O contexts
        {
            std::lock_guard<std::mutex> lock(self->io_mutex);
            while (!self->pending_reads.empty()) {
                IoContext* ctx = self->pending_reads.front();
                self->pending_reads.pop();
                if (ctx->buffer) free(ctx->buffer);
                free(ctx);
            }
            while (!self->pending_writes.empty()) {
                IoContext* ctx = self->pending_writes.front();
                self->pending_writes.pop();
                if (ctx->buffer) free(ctx->buffer);
                free(ctx);
            }
        }
        
        // Close process handle
        if (self->hProcess != INVALID_HANDLE_VALUE) {
            CloseHandle(self->hProcess);
            self->hProcess = INVALID_HANDLE_VALUE;
        }
        
        // Close pipe handles
        if (self->hInputPipeWrite != INVALID_HANDLE_VALUE) {
            CloseHandle(self->hInputPipeWrite);
            self->hInputPipeWrite = INVALID_HANDLE_VALUE;
        }
        
        if (self->hOutputPipeRead != INVALID_HANDLE_VALUE) {
            CloseHandle(self->hOutputPipeRead);
            self->hOutputPipeRead = INVALID_HANDLE_VALUE;
        }
        
        // Close pseudoconsole
        if (self->hPC) {
            initialize_conpty_api();
            if (pClosePseudoConsole && conpty_available) {
                pClosePseudoConsole(self->hPC);
            }
            self->hPC = nullptr;
        }
        
        DeleteCriticalSection(&self->lock);
    }
    
    Py_TYPE(self)->tp_free((PyObject*)self);
}

// Create a new ConPTY object
static PyObject* ConPTY_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
    ConPTYObject* self = reinterpret_cast<ConPTYObject*>(type->tp_alloc(type, 0));
    if (self) {
        self->hPC = nullptr;
        self->hInputPipeWrite = INVALID_HANDLE_VALUE;
        self->hOutputPipeRead = INVALID_HANDLE_VALUE;
        self->hProcess = INVALID_HANDLE_VALUE;
        self->dwProcessId = 0;
        self->closed = false;
        self->io_thread_running = false;
        self->io_thread_handle = INVALID_HANDLE_VALUE;
        InitializeCriticalSection(&self->lock);
    }
    return reinterpret_cast<PyObject*>(self);
}

// Initialize the ConPTY object with command and dimensions
static int ConPTY_init(ConPTYObject* self, PyObject* args, PyObject* kwds) {
    const char* command;
    unsigned short cols = 80;
    unsigned short rows = 24;
    const char* cwd = nullptr;
    PyObject* env_dict = nullptr;
    
    static const char* kwlist[] = {"command", "cols", "rows", "cwd", "env", nullptr};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|HHzO", (char**)kwlist, 
                                   &command, &cols, &rows, &cwd, &env_dict)) {
        return -1;
    }
    
    initialize_conpty_api();
    
    if (!conpty_available) {
        PyErr_SetString(PyExc_RuntimeError, "ConPTY API not available. Requires Windows 10 1809 or later.");
        return -1;
    }
    
    // Create pipes for the console
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hInputRead, hInputWrite;
    HANDLE hOutputRead, hOutputWrite;
    
    if (!CreatePipe(&hInputRead, &hInputWrite, &sa, 0)) {
        PyErr_SetFromWindowsErr(GetLastError());
        return -1;
    }
    
    if (!CreatePipe(&hOutputRead, &hOutputWrite, &sa, 0)) {
        CloseHandle(hInputRead);
        CloseHandle(hInputWrite);
        PyErr_SetFromWindowsErr(GetLastError());
        return -1;
    }
    
    // Set pipe modes for async I/O
    DWORD mode = PIPE_NOWAIT;
    if (!SetNamedPipeHandleState(hOutputRead, &mode, nullptr, nullptr)) {
        CloseHandle(hInputRead);
        CloseHandle(hInputWrite);
        CloseHandle(hOutputRead);
        CloseHandle(hOutputWrite);
        PyErr_SetFromWindowsErr(GetLastError());
        return -1;
    }
    
    // Create pseudoconsole
    COORD size = { static_cast<SHORT>(cols), static_cast<SHORT>(rows) };
    HRESULT hr = pCreatePseudoConsole(size, hInputRead, hOutputWrite, 0, &self->hPC);
    if (FAILED(hr)) {
        CloseHandle(hInputRead);
        CloseHandle(hInputWrite);
        CloseHandle(hOutputRead);
        CloseHandle(hOutputWrite);
        PyErr_Format(PyExc_RuntimeError, "CreatePseudoConsole failed with error 0x%08X", hr);
        return -1;
    }
    
    // CRITICAL FIX #2: Close the handles immediately after CreatePseudoConsole
    // ConPTY takes ownership of these handles
    CloseHandle(hInputRead);
    CloseHandle(hOutputWrite);
    
    // Store the handles we need to keep
    self->hInputPipeWrite = hInputWrite;   // We write to this to send input to console
    self->hOutputPipeRead = hOutputRead;   // We read from this to get output from console
    
    // Convert command to wide string
    int cmd_len = MultiByteToWideChar(CP_UTF8, 0, command, -1, nullptr, 0);
    wchar_t* command_wide = static_cast<wchar_t*>(malloc(cmd_len * sizeof(wchar_t)));
    if (!command_wide) {
        PyErr_NoMemory();
        return -1;
    }
    MultiByteToWideChar(CP_UTF8, 0, command, -1, command_wide, cmd_len);
    
    // Convert CWD to wide string if provided
    wchar_t* cwd_wide = nullptr;
    if (cwd) {
        int cwd_len = MultiByteToWideChar(CP_UTF8, 0, cwd, -1, nullptr, 0);
        cwd_wide = static_cast<wchar_t*>(malloc(cwd_len * sizeof(wchar_t)));
        if (!cwd_wide) {
            free(command_wide);
            PyErr_NoMemory();
            return -1;
        }
        MultiByteToWideChar(CP_UTF8, 0, cwd, -1, cwd_wide, cwd_len);
    }
    
    // Create environment block
    wchar_t* env_block = nullptr;
    if (env_dict && env_dict != Py_None) {
        if (!create_environment_block(env_dict, &env_block)) {
            free(command_wide);
            free(cwd_wide);
            return -1;
        }
    }
    
    // Create process attribute list
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(malloc(attrListSize));
    if (!attrList) {
        free(command_wide);
        free(cwd_wide);
        if (env_block) free(env_block);
        PyErr_NoMemory();
        return -1;
    }
    
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
        free(attrList);
        free(command_wide);
        free(cwd_wide);
        if (env_block) free(env_block);
        PyErr_SetFromWindowsErr(GetLastError());
        return -1;
    }
    
    // Update the attribute list to include the pseudoconsole
    if (!UpdateProcThreadAttribute(
        attrList,
        0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        &self->hPC,
        sizeof(HPCON),
        nullptr,
        nullptr)) {
        DeleteProcThreadAttributeList(attrList);
        free(attrList);
        free(command_wide);
        free(cwd_wide);
        if (env_block) free(env_block);
        PyErr_SetFromWindowsErr(GetLastError());
        return -1;
    }
    
    // Set up process creation - CRITICAL FIX #3: Do NOT set stdio handles
    STARTUPINFOEXW siEx = { 0 };
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siEx.lpAttributeList = attrList;
    
    PROCESS_INFORMATION pi = { 0 };
    
    // Create the process
    BOOL success = CreateProcessW(
        nullptr,
        command_wide,
        nullptr,
        nullptr,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        env_block,
        cwd_wide,
        &siEx.StartupInfo,
        &pi
    );
    
    // Clean up attributes and strings
    DeleteProcThreadAttributeList(attrList);
    free(attrList);
    free(command_wide);
    free(cwd_wide);
    if (env_block) free(env_block);
    
    if (!success) {
        DWORD err = GetLastError();
        CloseHandle(self->hInputPipeWrite);
        CloseHandle(self->hOutputPipeRead);
        self->hInputPipeWrite = INVALID_HANDLE_VALUE;
        self->hOutputPipeRead = INVALID_HANDLE_VALUE;
        pClosePseudoConsole(self->hPC);
        self->hPC = nullptr;
        PyErr_SetFromWindowsErr(err);
        return -1;
    }
    
    // Store process information
    self->hProcess = pi.hProcess;
    self->dwProcessId = pi.dwProcessId;
    CloseHandle(pi.hThread); // Don't need the thread handle
    
    // Start I/O completion thread
    self->io_thread_running = true;
    self->io_thread_handle = CreateThread(
        nullptr,
        0,
        io_completion_thread,
        self,
        0,
        nullptr
    );
    
    if (self->io_thread_handle == INVALID_HANDLE_VALUE) {
        self->io_thread_running = false;
        CloseHandle(self->hProcess);
        self->hProcess = INVALID_HANDLE_VALUE;
        CloseHandle(self->hInputPipeWrite);
        CloseHandle(self->hOutputPipeRead);
        self->hInputPipeWrite = INVALID_HANDLE_VALUE;
        self->hOutputPipeRead = INVALID_HANDLE_VALUE;
        pClosePseudoConsole(self->hPC);
        self->hPC = nullptr;
        PyErr_SetFromWindowsErr(GetLastError());
        return -1;
    }
    
    return 0;
}

// Get the process ID
static PyObject* ConPTY_get_pid(ConPTYObject* self, void* closure) {
    return PyLong_FromUnsignedLong(self->dwProcessId);
}

// Set echo mode on the console
static PyObject* ConPTY_set_echo(ConPTYObject* self, PyObject* args) {
    BOOL enable_echo;
    if (!PyArg_ParseTuple(args, "p", &enable_echo)) {
        return nullptr;
    }
    
    // CRITICAL FIX #4: Cannot use GetConsoleMode/SetConsoleMode on pipe handles
    // Instead, we need to get the actual console handle from the process
    PyErr_SetString(PyExc_NotImplementedError, 
        "Console echo control not supported in this implementation. "
        "Use process-level configuration instead.");
    return nullptr;
}

// Send a signal to the process
static PyObject* ConPTY_send_signal(ConPTYObject* self, PyObject* args) {
    int sig_type;
    if (!PyArg_ParseTuple(args, "i", &sig_type)) {
        return nullptr;
    }
    
    DWORD ctrl_type;
    switch (sig_type) {
        case 0: // Ctrl+C
            ctrl_type = CTRL_C_EVENT;
            break;
        case 1: // Ctrl+Break
            ctrl_type = CTRL_BREAK_EVENT;
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "Unsupported signal type. Use 0 for Ctrl+C, 1 for Ctrl+Break.");
            return nullptr;
    }
    
    // CRITICAL FIX #6: Use GenerateConsoleCtrlEvent with process group 0
    if (!GenerateConsoleCtrlEvent(ctrl_type, 0)) {
        PyErr_SetFromWindowsErr(GetLastError());
        return nullptr;
    }
    
    Py_RETURN_NONE;
}

// Async read operation
static PyObject* ConPTY_read_async(ConPTYObject* self) {
    EnterCriticalSection(&self->lock);
    
    if (self->closed) {
        LeaveCriticalSection(&self->lock);
        PyErr_SetString(PyExc_RuntimeError, "ConPTY is closed");
        return nullptr;
    }
    
    LeaveCriticalSection(&self->lock);
    
    // Create I/O context
    IoContext* ctx = static_cast<IoContext*>(malloc(sizeof(IoContext)));
    if (!ctx) {
        PyErr_NoMemory();
        return nullptr;
    }
    
    memset(&ctx->overlapped, 0, sizeof(OVERLAPPED));
    ctx->buffer = static_cast<char*>(malloc(4096));
    ctx->buffer_size = 4096;
    ctx->completed = false;
    ctx->overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ctx->buffer || ctx->overlapped.hEvent == INVALID_HANDLE_VALUE) {
        if (ctx->buffer) free(ctx->buffer);
        if (ctx->overlapped.hEvent != INVALID_HANDLE_VALUE) CloseHandle(ctx->overlapped.hEvent);
        free(ctx);
        PyErr_NoMemory();
        return nullptr;
    }
    
    // Start read operation
    DWORD bytes_read = 0;
    BOOL result = ReadFile(
        self->hOutputPipeRead,
        ctx->buffer,
        ctx->buffer_size,
        &bytes_read,
        &ctx->overlapped
    );
    
    DWORD error = GetLastError();
    if (!result && error != ERROR_IO_PENDING) {
        CloseHandle(ctx->overlapped.hEvent);
        free(ctx->buffer);
        free(ctx);
        PyErr_SetFromWindowsErr(error);
        return nullptr;
    }
    
    // Add to pending reads queue
    {
        std::lock_guard<std::mutex> lock(self->io_mutex);
        self->pending_reads.push(ctx);
        self->io_cv.notify_one();
    }
    
    // Create future for async completion
    PyObject* asyncio_module = PyImport_ImportModule("asyncio");
    if (!asyncio_module) {
        return nullptr;
    }
    
    PyObject* get_running_loop = PyObject_GetAttrString(asyncio_module, "get_running_loop");
    Py_DECREF(asyncio_module);
    if (!get_running_loop) {
        return nullptr;
    }
    
    PyObject* loop = PyObject_CallObject(get_running_loop, nullptr);
    Py_DECREF(get_running_loop);
    if (!loop) {
        return nullptr;
    }
    
    PyObject* create_future = PyObject_GetAttrString(loop, "create_future");
    Py_DECREF(loop);
    if (!create_future) {
        return nullptr;
    }
    
    PyObject* future = PyObject_CallObject(create_future, nullptr);
    Py_DECREF(create_future);
    if (!future) {
        return nullptr;
    }
    
    // Launch completion monitoring task
    std::thread([self, ctx, future]() {
        PyGILState_STATE gstate = PyGILState_Ensure();
        
        // Wait for completion
        while (!ctx->completed) {
            {
                std::unique_lock<std::mutex> lock(self->io_mutex);
                if (ctx->completed) break;
                self->io_cv.wait_for(lock, std::chrono::milliseconds(100));
            }
            
            if (self->closed) {
                // Cancel pending I/O if closed
                CancelIoEx(self->hOutputPipeRead, &ctx->overlapped);
                break;
            }
        }
        
        if (ctx->completed) {
            if (ctx->success && ctx->bytes_transferred > 0) {
                PyObject* data = PyBytes_FromStringAndSize(ctx->buffer, ctx->bytes_transferred);
                if (data) {
                    PyObject_CallMethod(future, "set_result", "O", data);
                    Py_DECREF(data);
                }
            } else {
                DWORD error = ctx->success ? 0 : GetLastError();
                if (error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF || self->closed) {
                    PyObject_CallMethod(future, "set_result", "y#", "", 0);
                } else {
                    PyObject* exc = PyErr_NewExceptionWithDoc(
                        "mop_conpty.ReadError", 
                        "Read operation failed", 
                        nullptr, 
                        nullptr
                    );
                    if (exc) {
                        PyObject_CallMethod(future, "set_exception", "O", exc);
                        Py_DECREF(exc);
                    }
                }
            }
        } else {
            // Operation was cancelled
            PyObject* exc = PyErr_NewExceptionWithDoc(
                "mop_conpty.CancelledError", 
                "Read operation was cancelled", 
                nullptr, 
                nullptr
            );
            if (exc) {
                PyObject_CallMethod(future, "set_exception", "O", exc);
                Py_DECREF(exc);
            }
        }
        
        // Clean up
        CloseHandle(ctx->overlapped.hEvent);
        free(ctx->buffer);
        free(ctx);
        Py_DECREF(future);
        PyGILState_Release(gstate);
    }).detach();
    
    return future;
}

// Async write operation
static PyObject* ConPTY_write_async(ConPTYObject* self, PyObject* args) {
    const char* data;
    Py_ssize_t length;
    if (!PyArg_ParseTuple(args, "y#", &data, &length)) {
        return nullptr;
    }
    
    EnterCriticalSection(&self->lock);
    
    if (self->closed) {
        LeaveCriticalSection(&self->lock);
        PyErr_SetString(PyExc_RuntimeError, "ConPTY is closed");
        return nullptr;
    }
    
    LeaveCriticalSection(&self->lock);
    
    // Create I/O context
    IoContext* ctx = static_cast<IoContext*>(malloc(sizeof(IoContext)));
    if (!ctx) {
        PyErr_NoMemory();
        return nullptr;
    }
    
    memset(&ctx->overlapped, 0, sizeof(OVERLAPPED));
    ctx->buffer = static_cast<char*>(malloc(length));
    ctx->buffer_size = static_cast<DWORD>(length);
    ctx->completed = false;
    ctx->overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ctx->buffer || ctx->overlapped.hEvent == INVALID_HANDLE_VALUE) {
        if (ctx->buffer) free(ctx->buffer);
        if (ctx->overlapped.hEvent != INVALID_HANDLE_VALUE) CloseHandle(ctx->overlapped.hEvent);
        free(ctx);
        PyErr_NoMemory();
        return nullptr;
    }
    
    memcpy(ctx->buffer, data, length);
    
    // Start write operation
    DWORD bytes_written = 0;
    BOOL result = WriteFile(
        self->hInputPipeWrite,
        ctx->buffer,
        ctx->buffer_size,
        &bytes_written,
        &ctx->overlapped
    );
    
    DWORD error = GetLastError();
    if (!result && error != ERROR_IO_PENDING) {
        CloseHandle(ctx->overlapped.hEvent);
        free(ctx->buffer);
        free(ctx);
        PyErr_SetFromWindowsErr(error);
        return nullptr;
    }
    
    // Add to pending writes queue
    {
        std::lock_guard<std::mutex> lock(self->io_mutex);
        self->pending_writes.push(ctx);
        self->io_cv.notify_one();
    }
    
    // Create future for async completion
    PyObject* asyncio_module = PyImport_ImportModule("asyncio");
    if (!asyncio_module) {
        return nullptr;
    }
    
    PyObject* get_running_loop = PyObject_GetAttrString(asyncio_module, "get_running_loop");
    Py_DECREF(asyncio_module);
    if (!get_running_loop) {
        return nullptr;
    }
    
    PyObject* loop = PyObject_CallObject(get_running_loop, nullptr);
    Py_DECREF(get_running_loop);
    if (!loop) {
        return nullptr;
    }
    
    PyObject* create_future = PyObject_GetAttrString(loop, "create_future");
    Py_DECREF(loop);
    if (!create_future) {
        return nullptr;
    }
    
    PyObject* future = PyObject_CallObject(create_future, nullptr);
    Py_DECREF(create_future);
    if (!future) {
        return nullptr;
    }
    
    // Launch completion monitoring task
    std::thread([self, ctx, future]() {
        PyGILState_STATE gstate = PyGILState_Ensure();
        
        // Wait for completion
        while (!ctx->completed) {
            {
                std::unique_lock<std::mutex> lock(self->io_mutex);
                if (ctx->completed) break;
                self->io_cv.wait_for(lock, std::chrono::milliseconds(100));
            }
            
            if (self->closed) {
                // Cancel pending I/O if closed
                CancelIoEx(self->hInputPipeWrite, &ctx->overlapped);
                break;
            }
        }
        
        if (ctx->completed) {
            if (ctx->success) {
                PyObject* result = PyLong_FromUnsignedLong(ctx->bytes_transferred);
                if (result) {
                    PyObject_CallMethod(future, "set_result", "O", result);
                    Py_DECREF(result);
                }
            } else {
                DWORD error = GetLastError();
                PyObject* exc = PyErr_NewExceptionWithDoc(
                    "mop_conpty.WriteError", 
                    "Write operation failed", 
                    nullptr, 
                    nullptr
                );
                if (exc) {
                    PyObject_CallMethod(future, "set_exception", "O", exc);
                    Py_DECREF(exc);
                }
            }
        } else {
            // Operation was cancelled
            PyObject* exc = PyErr_NewExceptionWithDoc(
                "mop_conpty.CancelledError", 
                "Write operation was cancelled", 
                nullptr, 
                nullptr
            );
            if (exc) {
                PyObject_CallMethod(future, "set_exception", "O", exc);
                Py_DECREF(exc);
            }
        }
        
        // Clean up
        CloseHandle(ctx->overlapped.hEvent);
        free(ctx->buffer);
        free(ctx);
        Py_DECREF(future);
        PyGILState_Release(gstate);
    }).detach();
    
    return future;
}

// Close the ConPTY
static PyObject* ConPTY_close(ConPTYObject* self) {
    EnterCriticalSection(&self->lock);
    
    if (!self->closed.exchange(true)) {
        // Cancel all pending I/O operations - CRITICAL FIX #7
        if (self->hOutputPipeRead != INVALID_HANDLE_VALUE) {
            CancelIoEx(self->hOutputPipeRead, nullptr);
        }
        if (self->hInputPipeWrite != INVALID_HANDLE_VALUE) {
            CancelIoEx(self->hInputPipeWrite, nullptr);
        }
        
        // Clean up resources will be handled in dealloc
    }
    
    LeaveCriticalSection(&self->lock);
    
    Py_RETURN_NONE;
}

// Method definitions
static PyMethodDef ConPTY_methods[] = {
    {"set_echo", reinterpret_cast<PyCFunction>(ConPTY_set_echo), METH_VARARGS, "Enable or disable echo input"},
    {"send_signal", reinterpret_cast<PyCFunction>(ConPTY_send_signal), METH_VARARGS, "Send a signal to the process (0=Ctrl+C, 1=Ctrl+Break)"},
    {"read_async", reinterpret_cast<PyCFunction>(ConPTY_read_async), METH_NOARGS, "Asynchronously read data from the terminal"},
    {"write_async", reinterpret_cast<PyCFunction>(ConPTY_write_async), METH_VARARGS, "Asynchronously write data to the terminal"},
    {"close", reinterpret_cast<PyCFunction>(ConPTY_close), METH_NOARGS, "Close the pseudoconsole and terminate the process"},
    {nullptr, nullptr, 0, nullptr}
};

// Property definitions
static PyGetSetDef ConPTY_properties[] = {
    {"pid", reinterpret_cast<getter>(ConPTY_get_pid), nullptr, "Process ID of the child process", nullptr},
    {nullptr, nullptr, nullptr, nullptr, nullptr}
};

// Type slots
static PyType_Slot ConPTY_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(ConPTY_dealloc)},
    {Py_tp_getattro, reinterpret_cast<void*>(PyObject_GenericGetAttr)},
    {Py_tp_setattro, reinterpret_cast<void*>(PyObject_GenericSetAttr)},
    {Py_tp_methods, ConPTY_methods},
    {Py_tp_getset, ConPTY_properties},
    {Py_tp_init, reinterpret_cast<void*>(ConPTY_init)},
    {Py_tp_new, reinterpret_cast<void*>(ConPTY_new)},
    {0, nullptr}
};

static PyType_Spec ConPTY_spec = {
    "mop_conpty.ConPTY",
    sizeof(ConPTYObject),
    0,
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    ConPTY_slots
};

// Module definition
static PyMethodDef module_methods[] = {
    {nullptr, nullptr, 0, nullptr}
};

static struct PyModuleDef mop_conpty_module = {
    PyModuleDef_HEAD_INIT,
    "mop_conpty",
    "High-performance Windows ConPTY extension",
    -1,
    module_methods,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};

PyMODINIT_FUNC PyInit_mop_conpty() {
    PyObject* module = PyModule_Create(&mop_conpty_module);
    if (!module) {
        return nullptr;
    }
    
    // Create the ConPTY type
    PyObject* type = PyType_FromSpec(&ConPTY_spec);
    if (!type) {
        Py_DECREF(module);
        return nullptr;
    }
    
    // Add the type to the module
    if (PyModule_AddObject(module, "ConPTY", type) < 0) {
        Py_DECREF(type);
        Py_DECREF(module);
        return nullptr;
    }
    
    // Initialize ConPTY API availability
    initialize_conpty_api();
    
    return module;
}