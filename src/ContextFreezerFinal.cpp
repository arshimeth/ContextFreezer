#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h> 
#include <vector>
#include <string>
#include <algorithm>
#include <set>
#include <cwctype> 


#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib") 

using namespace System;
using namespace System::Runtime::InteropServices; 




static std::wstring ToNativeString(System::String^ sysStr) {
    if (System::String::IsNullOrEmpty(sysStr)) return std::wstring(L"");

   
    IntPtr ip = Marshal::StringToHGlobalUni(sysStr);
    std::wstring str = static_cast<const wchar_t*>(ip.ToPointer());
    Marshal::FreeHGlobal(ip); 
    return str;
}

static std::set<std::wstring> GetWhitelist() {
    return {
        L"explorer.exe", L"svchost.exe", L"csrss.exe", L"winlogon.exe",
        L"dwm.exe", L"system", L"registry", L"smss.exe", L"services.exe",
        L"lsass.exe", L"wininit.exe", L"spoolsv.exe", L"taskhostw.exe",
        L"contextfreezerfinal.exe"
    };
}

bool IsCriticalProcess(std::wstring name) {
    std::set<std::wstring> whitelist = GetWhitelist();
    std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return std::towlower(c); });
    return whitelist.count(name) > 0;
}

struct ProcessInfo {
    std::wstring name;
    DWORD pid;
    SIZE_T memoryUsage;
};

static bool CompareProcessInfo(const ProcessInfo& a, const ProcessInfo& b) {
    return a.memoryUsage > b.memoryUsage;
}

static std::vector<ProcessInfo> GetTopMemoryProcesses() {
    std::vector<ProcessInfo> processList;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) return processList;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    ProcessInfo pi;
                    pi.name = pe32.szExeFile;
                    pi.pid = pe32.th32ProcessID;
                    pi.memoryUsage = pmc.WorkingSetSize;
                    if (pi.memoryUsage > 10 * 1024 * 1024) processList.push_back(pi);
                }
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    std::sort(processList.begin(), processList.end(), CompareProcessInfo);
    return processList;
}

static bool IsProcessRunning(std::wstring processName) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe32; pe32.dwSize = sizeof(PROCESSENTRY32W);
    bool found = false;
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            std::wstring current = pe32.szExeFile;
            std::transform(current.begin(), current.end(), current.begin(), [](wchar_t c) { return std::towlower(c); });
            std::transform(processName.begin(), processName.end(), processName.begin(), [](wchar_t c) { return std::towlower(c); });
            if (current == processName) { found = true; break; }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return found;
}

static std::vector<DWORD> GetPidsNative(std::wstring processName) {
    std::vector<DWORD> pids;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe32; pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            std::wstring currentName = pe32.szExeFile;
            if (IsCriticalProcess(currentName)) continue;

            std::transform(currentName.begin(), currentName.end(), currentName.begin(), [](wchar_t c) { return std::towlower(c); });
            std::transform(processName.begin(), processName.end(), processName.begin(), [](wchar_t c) { return std::towlower(c); });

            if (currentName.find(processName) != std::wstring::npos) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return pids;
}

static bool TrimMemoryNative(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;
    BOOL res = SetProcessWorkingSetSize(hProcess, (SIZE_T)-1, (SIZE_T)-1);
    CloseHandle(hProcess);
    return res != 0;
}

static void SuspendNative(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te32; te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) { SuspendThread(hThread); CloseHandle(hThread); }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);
}

static void ResumeNative(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te32; te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) { ResumeThread(hThread); CloseHandle(hThread); }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);
}

static void GetDebugPrivilege() {
    HANDLE hToken; TOKEN_PRIVILEGES tp; LUID luid;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}


using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Collections::Generic;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;
using namespace System::IO;

namespace ContextFreezerGUI {

    public ref class ProfileData {
    public:
        List<String^>^ Apps;
        String^ TriggerApp;
        bool AutoFrozen;

        ProfileData() {
            Apps = gcnew List<String^>();
            TriggerApp = "";
            AutoFrozen = false;
        }
    };

    public ref class MyForm : public System::Windows::Forms::Form
    {
    public:
        MyForm(void)
        {
            InitializeComponent();
            GetDebugPrivilege();
            LoadConfig();
            UpdateLanguage();
        }

    protected:
        ~MyForm()
        {
            if (components) delete components;
        }

        void OnFormClosing(System::Windows::Forms::FormClosingEventArgs^ e) override {
            SaveConfig();
            if (e->CloseReason == CloseReason::UserClosing) {
                e->Cancel = true;
                this->Hide();
                notifyIcon->ShowBalloonTip(3000, "ContextFreezer", (isTr ? "Arka planda calisiyor..." : "Running in background..."), ToolTipIcon::Info);
            }
        }

    private:
        void LogToScreen(String^ msg) {
            if (logBox != nullptr) {
                logBox->AppendText(msg + "\n");
                logBox->ScrollToCaret();
            }
        }

        Panel^ leftPanel;
        Panel^ centerPanel;
        Panel^ rightPanel;

        Label^ lblBrand;
        ListBox^ listProfiles;
        TextBox^ txtNewProfile;
        Button^ btnAddProfile;

        GroupBox^ grpAuto;
        Label^ lblTriggerInfo;
        TextBox^ txtTriggerApp;
        Button^ btnSetTrigger;
        Timer^ autoTimer;
        CheckBox^ chkAutoMode;

        Label^ lblSelectedProfile;
        Button^ btnFreeze;
        Button^ btnThaw;
        RichTextBox^ logBox;
        Button^ btnLangSwitch;

        Label^ lblMonitorHeader;
        ListView^ listMonitor;
        Button^ btnAddFromMonitor;
        Button^ btnRefreshMonitor;
        Button^ btnExport;
        Button^ btnImport;

        NotifyIcon^ notifyIcon;
        System::Windows::Forms::ContextMenuStrip^ trayMenu;

        System::ComponentModel::Container^ components;
        Dictionary<String^, ProfileData^>^ profiles;
        bool isTr = true;
        String^ configPath = "profiles.cfg";

        void InitializeComponent(void)
        {
            this->components = gcnew System::ComponentModel::Container();
            this->Size = System::Drawing::Size(1200, 700);
            this->Text = L"ContextFreezer v5.2 Final";
            this->StartPosition = FormStartPosition::CenterScreen;
            this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedSingle;
            this->MaximizeBox = false;
            this->BackColor = Color::FromArgb(32, 32, 32);
            this->ForeColor = Color::White;

            this->notifyIcon = gcnew NotifyIcon(this->components);
            this->notifyIcon->Icon = SystemIcons::Application;
            this->notifyIcon->Text = "ContextFreezer";
            this->notifyIcon->Visible = true;
            this->notifyIcon->DoubleClick += gcnew EventHandler(this, &MyForm::OnTrayDoubleClick);

            this->trayMenu = gcnew System::Windows::Forms::ContextMenuStrip();
            this->trayMenu->Items->Add("Goster / Show", nullptr, gcnew EventHandler(this, &MyForm::OnTrayShow));
            this->trayMenu->Items->Add("Cikis / Exit", nullptr, gcnew EventHandler(this, &MyForm::OnTrayExit));
            this->notifyIcon->ContextMenuStrip = this->trayMenu;

            this->autoTimer = gcnew Timer(this->components);
            this->autoTimer->Interval = 3000;
            this->autoTimer->Tick += gcnew EventHandler(this, &MyForm::OnAutoTimerTick);

            this->leftPanel = (gcnew Panel());
            this->centerPanel = (gcnew Panel());
            this->rightPanel = (gcnew Panel());

            this->leftPanel->Dock = DockStyle::Left;
            this->leftPanel->Width = 240;
            this->leftPanel->BackColor = Color::FromArgb(40, 40, 40);
            this->leftPanel->Padding = System::Windows::Forms::Padding(10);

            this->lblBrand = (gcnew Label());
            this->lblBrand->Dock = DockStyle::Top;
            this->lblBrand->Height = 40;
            this->lblBrand->Font = (gcnew System::Drawing::Font(L"Segoe UI", 14, FontStyle::Bold));
            this->lblBrand->TextAlign = ContentAlignment::MiddleCenter;

            this->listProfiles = (gcnew ListBox());
            this->listProfiles->Dock = DockStyle::Fill;
            this->listProfiles->BackColor = Color::FromArgb(50, 50, 50);
            this->listProfiles->ForeColor = Color::WhiteSmoke;
            this->listProfiles->BorderStyle = System::Windows::Forms::BorderStyle::None;
            this->listProfiles->Font = (gcnew System::Drawing::Font(L"Segoe UI", 11));
            this->listProfiles->ItemHeight = 25;
            this->listProfiles->SelectedIndexChanged += gcnew EventHandler(this, &MyForm::OnProfileChanged);

            this->txtNewProfile = (gcnew TextBox());
            this->txtNewProfile->Dock = DockStyle::Bottom;
            this->txtNewProfile->BackColor = Color::FromArgb(60, 60, 60);
            this->txtNewProfile->ForeColor = Color::White;
            this->txtNewProfile->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;

            this->btnAddProfile = (gcnew Button());
            this->btnAddProfile->Dock = DockStyle::Bottom;
            this->btnAddProfile->Height = 35;
            this->btnAddProfile->FlatStyle = FlatStyle::Flat;
            this->btnAddProfile->BackColor = Color::FromArgb(46, 204, 113);
            this->btnAddProfile->ForeColor = Color::White;
            this->btnAddProfile->FlatAppearance->BorderSize = 0;
            this->btnAddProfile->Click += gcnew EventHandler(this, &MyForm::OnAddProfile);

            Panel^ ioPanel = gcnew Panel();
            ioPanel->Dock = DockStyle::Bottom;
            ioPanel->Height = 40;

            this->btnImport = (gcnew Button());
            this->btnImport->Width = 105;
            this->btnImport->Dock = DockStyle::Left;
            this->btnImport->FlatStyle = FlatStyle::Flat;
            this->btnImport->BackColor = Color::FromArgb(52, 73, 94);
            this->btnImport->ForeColor = Color::White;
            this->btnImport->FlatAppearance->BorderSize = 0;
            this->btnImport->Click += gcnew EventHandler(this, &MyForm::OnImport);

            this->btnExport = (gcnew Button());
            this->btnExport->Width = 105;
            this->btnExport->Dock = DockStyle::Right;
            this->btnExport->FlatStyle = FlatStyle::Flat;
            this->btnExport->BackColor = Color::FromArgb(52, 73, 94);
            this->btnExport->ForeColor = Color::White;
            this->btnExport->FlatAppearance->BorderSize = 0;
            this->btnExport->Click += gcnew EventHandler(this, &MyForm::OnExport);

            ioPanel->Controls->Add(this->btnExport);
            ioPanel->Controls->Add(this->btnImport);

            Panel^ spacer = gcnew Panel(); spacer->Dock = DockStyle::Bottom; spacer->Height = 10;
            Panel^ spacer2 = gcnew Panel(); spacer2->Dock = DockStyle::Bottom; spacer2->Height = 10;
            Panel^ spacer3 = gcnew Panel(); spacer3->Dock = DockStyle::Bottom; spacer3->Height = 10;

            this->leftPanel->Controls->Add(this->listProfiles);
            this->leftPanel->Controls->Add(spacer);
            this->leftPanel->Controls->Add(this->txtNewProfile);
            this->leftPanel->Controls->Add(spacer2);
            this->leftPanel->Controls->Add(this->btnAddProfile);
            this->leftPanel->Controls->Add(spacer3);
            this->leftPanel->Controls->Add(ioPanel);
            this->leftPanel->Controls->Add(this->lblBrand);

            this->rightPanel->Dock = DockStyle::Right;
            this->rightPanel->Width = 350;
            this->rightPanel->BackColor = Color::FromArgb(25, 25, 25);
            this->rightPanel->Padding = System::Windows::Forms::Padding(15);

            this->lblMonitorHeader = (gcnew Label());
            this->lblMonitorHeader->Dock = DockStyle::Top;
            this->lblMonitorHeader->Height = 30;
            this->lblMonitorHeader->Font = (gcnew System::Drawing::Font(L"Consolas", 12, FontStyle::Bold));
            this->lblMonitorHeader->ForeColor = Color::FromArgb(0, 255, 0);
            this->lblMonitorHeader->TextAlign = ContentAlignment::MiddleLeft;

            this->btnRefreshMonitor = (gcnew Button());
            this->btnRefreshMonitor->Dock = DockStyle::Top;
            this->btnRefreshMonitor->Height = 30;
            this->btnRefreshMonitor->FlatStyle = FlatStyle::Flat;
            this->btnRefreshMonitor->BackColor = Color::FromArgb(40, 40, 40);
            this->btnRefreshMonitor->ForeColor = Color::LightGray;
            this->btnRefreshMonitor->FlatAppearance->BorderColor = Color::Gray;
            this->btnRefreshMonitor->Click += gcnew EventHandler(this, &MyForm::OnRefreshMonitor);

            this->listMonitor = (gcnew ListView());
            this->listMonitor->Dock = DockStyle::Fill;
            this->listMonitor->View = View::Details;
            this->listMonitor->FullRowSelect = true;
            this->listMonitor->GridLines = true;
            this->listMonitor->BackColor = Color::Black;
            this->listMonitor->ForeColor = Color::Lime;
            this->listMonitor->Font = (gcnew System::Drawing::Font(L"Consolas", 9));
            this->listMonitor->Columns->Add("App Name", 180);
            this->listMonitor->Columns->Add("RAM (MB)", 100);

            this->btnAddFromMonitor = (gcnew Button());
            this->btnAddFromMonitor->Dock = DockStyle::Bottom;
            this->btnAddFromMonitor->Height = 40;
            this->btnAddFromMonitor->FlatStyle = FlatStyle::Flat;
            this->btnAddFromMonitor->BackColor = Color::FromArgb(41, 128, 185);
            this->btnAddFromMonitor->ForeColor = Color::White;
            this->btnAddFromMonitor->FlatAppearance->BorderSize = 0;
            this->btnAddFromMonitor->Click += gcnew EventHandler(this, &MyForm::OnAddFromMonitor);

            Panel^ spacerMonitor = gcnew Panel(); spacerMonitor->Dock = DockStyle::Top; spacerMonitor->Height = 10;
            Panel^ spacerMonitor2 = gcnew Panel(); spacerMonitor2->Dock = DockStyle::Bottom; spacerMonitor2->Height = 10;

            this->rightPanel->Controls->Add(this->listMonitor);
            this->rightPanel->Controls->Add(spacerMonitor);
            this->rightPanel->Controls->Add(this->btnRefreshMonitor);
            this->rightPanel->Controls->Add(this->lblMonitorHeader);
            this->rightPanel->Controls->Add(spacerMonitor2);
            this->rightPanel->Controls->Add(this->btnAddFromMonitor);

            this->centerPanel->Dock = DockStyle::Fill;
            this->centerPanel->Padding = System::Windows::Forms::Padding(20);

            this->btnLangSwitch = (gcnew Button());
            this->btnLangSwitch->Size = System::Drawing::Size(40, 30);
            this->btnLangSwitch->Location = System::Drawing::Point(480, 10);
            this->btnLangSwitch->FlatStyle = FlatStyle::Flat;
            this->btnLangSwitch->BackColor = Color::Transparent;
            this->btnLangSwitch->ForeColor = Color::Gray;
            this->btnLangSwitch->FlatAppearance->BorderSize = 1;
            this->btnLangSwitch->FlatAppearance->BorderColor = Color::Gray;
            this->btnLangSwitch->Click += gcnew EventHandler(this, &MyForm::OnSwitchLang);

            this->lblSelectedProfile = (gcnew Label());
            this->lblSelectedProfile->Location = System::Drawing::Point(20, 20);
            this->lblSelectedProfile->Size = System::Drawing::Size(400, 30);
            this->lblSelectedProfile->Font = (gcnew System::Drawing::Font(L"Segoe UI", 12));
            this->lblSelectedProfile->ForeColor = Color::LightGray;

            this->btnFreeze = (gcnew Button());
            this->btnFreeze->Location = System::Drawing::Point(20, 60);
            this->btnFreeze->Size = System::Drawing::Size(240, 60);
            this->btnFreeze->FlatStyle = FlatStyle::Flat;
            this->btnFreeze->BackColor = Color::FromArgb(52, 152, 219);
            this->btnFreeze->ForeColor = Color::White;
            this->btnFreeze->Font = (gcnew System::Drawing::Font(L"Segoe UI", 12, FontStyle::Bold));
            this->btnFreeze->FlatAppearance->BorderSize = 0;
            this->btnFreeze->Click += gcnew EventHandler(this, &MyForm::OnFreeze);

            this->btnThaw = (gcnew Button());
            this->btnThaw->Location = System::Drawing::Point(270, 60);
            this->btnThaw->Size = System::Drawing::Size(240, 60);
            this->btnThaw->FlatStyle = FlatStyle::Flat;
            this->btnThaw->BackColor = Color::FromArgb(231, 76, 60);
            this->btnThaw->ForeColor = Color::White;
            this->btnThaw->Font = (gcnew System::Drawing::Font(L"Segoe UI", 12, FontStyle::Bold));
            this->btnThaw->FlatAppearance->BorderSize = 0;
            this->btnThaw->Click += gcnew EventHandler(this, &MyForm::OnThaw);

            this->grpAuto = (gcnew GroupBox());
            this->grpAuto->Location = System::Drawing::Point(20, 130);
            this->grpAuto->Size = System::Drawing::Size(490, 80);
            this->grpAuto->ForeColor = Color::Orange;
            this->grpAuto->Text = "GAME BOOSTER (Auto-Trigger)";

            this->lblTriggerInfo = (gcnew Label());
            this->lblTriggerInfo->Location = System::Drawing::Point(15, 25);
            this->lblTriggerInfo->Size = System::Drawing::Size(120, 20);
            this->lblTriggerInfo->Text = "Tetikleyici (.exe):";
            this->lblTriggerInfo->ForeColor = Color::White;

            this->txtTriggerApp = (gcnew TextBox());
            this->txtTriggerApp->Location = System::Drawing::Point(140, 22);
            this->txtTriggerApp->Size = System::Drawing::Size(250, 20);
            this->txtTriggerApp->BackColor = Color::FromArgb(50, 50, 50);
            this->txtTriggerApp->ForeColor = Color::White;
            this->txtTriggerApp->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;

            this->btnSetTrigger = (gcnew Button());
            this->btnSetTrigger->Text = "KAYDET";
            this->btnSetTrigger->Location = System::Drawing::Point(400, 20);
            this->btnSetTrigger->Size = System::Drawing::Size(80, 24);
            this->btnSetTrigger->FlatStyle = FlatStyle::Flat;
            this->btnSetTrigger->BackColor = Color::Orange;
            this->btnSetTrigger->ForeColor = Color::Black;
            this->btnSetTrigger->Click += gcnew EventHandler(this, &MyForm::OnSetTrigger);

            this->chkAutoMode = (gcnew CheckBox());
            this->chkAutoMode->Text = "OTOMATIK MODU AKTIFLESTIR (Arka Planda Tarar)";
            this->chkAutoMode->Location = System::Drawing::Point(20, 50);
            this->chkAutoMode->AutoSize = true;
            this->chkAutoMode->ForeColor = Color::LightGreen;
            this->chkAutoMode->CheckedChanged += gcnew EventHandler(this, &MyForm::OnAutoCheckChanged);

            this->grpAuto->Controls->Add(this->chkAutoMode);
            this->grpAuto->Controls->Add(this->btnSetTrigger);
            this->grpAuto->Controls->Add(this->txtTriggerApp);
            this->grpAuto->Controls->Add(this->lblTriggerInfo);

            this->logBox = (gcnew RichTextBox());
            this->logBox->Location = System::Drawing::Point(20, 230);
            this->logBox->Size = System::Drawing::Size(490, 400);
            this->logBox->BackColor = Color::FromArgb(20, 20, 20);
            this->logBox->ForeColor = Color::LimeGreen;
            this->logBox->BorderStyle = System::Windows::Forms::BorderStyle::None;
            this->logBox->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
            this->logBox->ReadOnly = true;

            this->centerPanel->Controls->Add(this->grpAuto);
            this->centerPanel->Controls->Add(this->btnLangSwitch);
            this->centerPanel->Controls->Add(this->logBox);
            this->centerPanel->Controls->Add(this->btnThaw);
            this->centerPanel->Controls->Add(this->btnFreeze);
            this->centerPanel->Controls->Add(this->lblSelectedProfile);

            this->Controls->Add(this->centerPanel);
            this->Controls->Add(this->rightPanel);
            this->Controls->Add(this->leftPanel);
        }

        void UpdateLanguage() {
            if (isTr) {
                lblBrand->Text = "PROFILLER";
                btnAddProfile->Text = "+ Yeni Profil";
                btnFreeze->Text = "DONDUR";
                btnThaw->Text = "UYANDIR";
                lblMonitorHeader->Text = "> SYSTEM_MONITOR";
                btnRefreshMonitor->Text = "YENILE";
                btnAddFromMonitor->Text = "<< SECILENI EKLE";
                btnLangSwitch->Text = "EN";
                grpAuto->Text = "GAME BOOSTER (Auto-Trigger)";
                lblTriggerInfo->Text = "Tetikleyici (.exe):";
                btnSetTrigger->Text = "KAYDET";
                chkAutoMode->Text = "OTOMATIK MODU AKTIFLESTIR";
                btnImport->Text = "Ice Aktar";
                btnExport->Text = "Disa Aktar";
            }
            else {
                lblBrand->Text = "PROFILES";
                btnAddProfile->Text = "+ New Profile";
                btnFreeze->Text = "FREEZE";
                btnThaw->Text = "THAW";
                lblMonitorHeader->Text = "> SYSTEM_MONITOR";
                btnRefreshMonitor->Text = "REFRESH";
                btnAddFromMonitor->Text = "<< ADD SELECTED";
                btnLangSwitch->Text = "TR";
                grpAuto->Text = "GAME BOOSTER (Auto-Trigger)";
                lblTriggerInfo->Text = "Trigger App (.exe):";
                btnSetTrigger->Text = "SAVE";
                chkAutoMode->Text = "ENABLE AUTO MODE";
                btnImport->Text = "Import";
                btnExport->Text = "Export";
            }
        }

        void SaveConfig() {
            try {
                StreamWriter^ sw = gcnew StreamWriter(configPath);
                for each(auto item in profiles) {
                    sw->Write(item.Key + "=" + item.Value->TriggerApp + "|");
                    for (int i = 0; i < item.Value->Apps->Count; i++) {
                        sw->Write(item.Value->Apps[i]);
                        if (i < item.Value->Apps->Count - 1) sw->Write(",");
                    }
                    sw->WriteLine();
                }
                sw->Close();
            }
            catch (...) {}
        }

        void LoadConfig() {
            if (!File::Exists(configPath)) {
                profiles = gcnew Dictionary<String^, ProfileData^>();
                ProfileData^ p = gcnew ProfileData();
                p->Apps->Add("SearchApp.exe"); p->Apps->Add("OneDrive.exe");
                profiles["Oyun Modu"] = p;
                UpdateProfileList();
                return;
            }

            profiles = gcnew Dictionary<String^, ProfileData^>();
            try {
                StreamReader^ sr = gcnew StreamReader(configPath);
                String^ line;
                while ((line = sr->ReadLine()) != nullptr) {
                    array<String^>^ mainParts = line->Split('=');
                    if (mainParts->Length == 2) {
                        String^ pName = mainParts[0];
                        array<String^>^ dataParts = mainParts[1]->Split('|');

                        ProfileData^ p = gcnew ProfileData();
                        if (dataParts->Length > 0) p->TriggerApp = dataParts[0];

                        if (dataParts->Length > 1) {
                            array<String^>^ apps = dataParts[1]->Split(',');
                            for each(String ^ app in apps) if (!String::IsNullOrWhiteSpace(app)) p->Apps->Add(app);
                        }
                        profiles[pName] = p;
                    }
                }
                sr->Close();
                UpdateProfileList();
            }
            catch (...) {}
        }

        void RefreshMonitorList() {
            listMonitor->Items->Clear();
            std::vector<ProcessInfo> topApps = GetTopMemoryProcesses();
            for (const auto& app : topApps) {
                
                String^ name = gcnew String(app.name.c_str());
                double mb = app.memoryUsage / (1024.0 * 1024.0);
                ListViewItem^ item = gcnew ListViewItem(name);
                item->SubItems->Add(mb.ToString("F1") + " MB");
                listMonitor->Items->Add(item);
            }
        }

        void UpdateProfileList() {
            listProfiles->Items->Clear();
            for each(auto item in profiles) {
                listProfiles->Items->Add(item.Key);
            }
        }

        void OnSwitchLang(Object^ sender, EventArgs^ e) {
            isTr = !isTr;
            UpdateLanguage();
        }

        void OnAddProfile(Object^ sender, EventArgs^ e) {
            String^ name = txtNewProfile->Text;
            if (!String::IsNullOrWhiteSpace(name) && !profiles->ContainsKey(name)) {
                profiles[name] = gcnew ProfileData();
                UpdateProfileList();
                txtNewProfile->Text = "";
            }
        }

        void OnProfileChanged(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem != nullptr) {
                String^ selected = listProfiles->SelectedItem->ToString();
                ProfileData^ p = profiles[selected];

                lblSelectedProfile->Text = (isTr ? "Secili: " : "Selected: ") + selected;
                txtTriggerApp->Text = p->TriggerApp;

                logBox->Clear();
                LogToScreen("--- " + selected + " ---");
                if (p->TriggerApp != "") LogToScreen("AUTO-TRIGGER: " + p->TriggerApp);
                for each(String ^ app in p->Apps) {
                    LogToScreen(">> " + app);
                }
            }
        }

        void OnTrayDoubleClick(Object^ sender, EventArgs^ e) { this->Show(); this->WindowState = FormWindowState::Normal; }
        void OnTrayShow(Object^ sender, EventArgs^ e) { this->Show(); this->WindowState = FormWindowState::Normal; }
        void OnTrayExit(Object^ sender, EventArgs^ e) { SaveConfig(); Application::Exit(); }

        void OnSetTrigger(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem == nullptr) return;
            String^ selected = listProfiles->SelectedItem->ToString();
            profiles[selected]->TriggerApp = txtTriggerApp->Text;
            MessageBox::Show("Trigger Saved!");
            SaveConfig();
        }

        void OnAutoCheckChanged(Object^ sender, EventArgs^ e) {
            if (chkAutoMode->Checked) {
                autoTimer->Start();
                LogToScreen("[AUTO] Scanner Started...");
            }
            else {
                autoTimer->Stop();
                LogToScreen("[AUTO] Scanner Stopped.");
            }
        }

        void OnAutoTimerTick(Object^ sender, EventArgs^ e) {
            for each(auto item in profiles) {
                ProfileData^ p = item.Value;
                if (String::IsNullOrWhiteSpace(p->TriggerApp)) continue;

           
                std::wstring wTrigger = ToNativeString(p->TriggerApp);
                bool isRunning = IsProcessRunning(wTrigger);

                if (isRunning && !p->AutoFrozen) {
                    p->AutoFrozen = true;
                    LogToScreen("[AUTO] " + p->TriggerApp + " Detected! Freezing " + item.Key + "...");
                    FreezeProfile(item.Key);
                }
                else if (!isRunning && p->AutoFrozen) {
                    p->AutoFrozen = false;
                    LogToScreen("[AUTO] " + p->TriggerApp + " Closed. Thawing " + item.Key + "...");
                    ThawProfile(item.Key);
                }
            }
        }

        void OnRefreshMonitor(Object^ sender, EventArgs^ e) { RefreshMonitorList(); }

        void OnAddFromMonitor(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem == nullptr) return;
            if (listMonitor->SelectedItems->Count == 0) return;

            String^ appName = listMonitor->SelectedItems[0]->Text;
      
            std::wstring wAppName = ToNativeString(appName);

            if (IsCriticalProcess(wAppName)) {
                MessageBox::Show("Bu sistem dosyasi dondurulamaz!", "GUVENLIK UYARISI", MessageBoxButtons::OK, MessageBoxIcon::Error);
                return;
            }

            String^ currentProfile = listProfiles->SelectedItem->ToString();
            if (!profiles[currentProfile]->Apps->Contains(appName)) {
                profiles[currentProfile]->Apps->Add(appName);
                OnProfileChanged(nullptr, nullptr);
            }
        }

        void FreezeProfile(String^ profileName) {
            List<String^>^ apps = profiles[profileName]->Apps;
            for each(String ^ app in apps) {
             
                std::wstring nativeName = ToNativeString(app);
                std::vector<DWORD> pids = GetPidsNative(nativeName);
                if (!pids.empty()) {
                    for (DWORD pid : pids) {
                        SuspendNative(pid);
                        TrimMemoryNative(pid);
                        LogToScreen("[*] " + app + " -> FREEZED");
                    }
                }
            }
        }

        void ThawProfile(String^ profileName) {
            List<String^>^ apps = profiles[profileName]->Apps;
            for each(String ^ app in apps) {
         
                std::wstring nativeName = ToNativeString(app);
                std::vector<DWORD> pids = GetPidsNative(nativeName);
                for (DWORD pid : pids) {
                    ResumeNative(pid);
                    LogToScreen("[+] " + app + " -> ACTIVE");
                }
            }
        }

        void OnFreeze(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem == nullptr) return;
            LogToScreen("\n[ FREEZING... ]");
            FreezeProfile(listProfiles->SelectedItem->ToString());
            LogToScreen("--- DONE ---");
        }

        void OnThaw(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem == nullptr) return;
            LogToScreen("\n[ THAWING... ]");
            ThawProfile(listProfiles->SelectedItem->ToString());
            LogToScreen("--- DONE ---");
        }

        void OnExport(Object^ sender, EventArgs^ e) {
            SaveFileDialog^ sfd = gcnew SaveFileDialog();
            sfd->Filter = "ContextFreezer Profile (*.cfreezer)|*.cfreezer";

            if (sfd->ShowDialog() == System::Windows::Forms::DialogResult::OK) {
                StreamWriter^ sw = gcnew StreamWriter(sfd->FileName);
                for each(auto item in profiles) {
                    sw->Write(item.Key + "=" + item.Value->TriggerApp + "|");
                    for (int i = 0; i < item.Value->Apps->Count; i++) {
                        sw->Write(item.Value->Apps[i]);
                        if (i < item.Value->Apps->Count - 1) sw->Write(",");
                    }
                    sw->WriteLine();
                }
                sw->Close();
                MessageBox::Show(isTr ? "Yedeklendi!" : "Exported!");
            }
        }

        void OnImport(Object^ sender, EventArgs^ e) {
            OpenFileDialog^ ofd = gcnew OpenFileDialog();
            ofd->Filter = "ContextFreezer Profile (*.cfreezer)|*.cfreezer";

            if (ofd->ShowDialog() == System::Windows::Forms::DialogResult::OK) {
                StreamReader^ sr = gcnew StreamReader(ofd->FileName);
                String^ line;
                while ((line = sr->ReadLine()) != nullptr) {
                    array<String^>^ mainParts = line->Split('=');
                    if (mainParts->Length == 2) {
                        String^ pName = mainParts[0];
                        array<String^>^ dataParts = mainParts[1]->Split('|');

                        ProfileData^ p = gcnew ProfileData();
                        if (dataParts->Length > 0) p->TriggerApp = dataParts[0];

                        if (dataParts->Length > 1) {
                            array<String^>^ apps = dataParts[1]->Split(',');
                            for each(String ^ app in apps) if (!String::IsNullOrWhiteSpace(app)) p->Apps->Add(app);
                        }

                        if (!profiles->ContainsKey(pName)) {
                            profiles[pName] = p;
                        }
                        else {
                            profiles[pName] = p; 
                        }
                    }
                }
                sr->Close();
                UpdateProfileList();
                MessageBox::Show(isTr ? "Profiller Yuklendi!" : "Profiles Imported!");
            }
        }
    };
}

[STAThread]
int main(array<System::String^>^ args)
{
    Application::EnableVisualStyles();
    Application::SetCompatibleTextRenderingDefault(false);
    ContextFreezerGUI::MyForm form;
    Application::Run(% form);
    return 0;
}