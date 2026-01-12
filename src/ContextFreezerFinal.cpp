#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <set> 
#include <msclr/marshal_cppstd.h> 


#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")




static std::vector<std::wstring> GetRunningAppsNative() {
    std::set<std::wstring> uniqueApps; 
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) return std::vector<std::wstring>();

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
          
            std::wstring appName = pe32.szExeFile;
            if (appName.length() > 0 && appName.find(L".exe") != std::wstring::npos) {
                uniqueApps.insert(appName);
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);

  
    return std::vector<std::wstring>(uniqueApps.begin(), uniqueApps.end());
}

static std::vector<DWORD> GetPidsNative(std::wstring processName) {
    std::vector<DWORD> pids;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            std::wstring currentName = pe32.szExeFile;
            std::transform(currentName.begin(), currentName.end(), currentName.begin(), ::tolower);
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

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
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);
}

static void ResumeNative(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);
}

static void GetDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
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

    public ref class MyForm : public System::Windows::Forms::Form
    {
    public:
        MyForm(void)
        {
            InitializeComponent();
            GetDebugPrivilege();
            InitializeData();
        }

    protected:
        ~MyForm()
        {
            if (components) delete components;
        }

    private:
        System::Windows::Forms::Panel^ leftPanel;
        System::Windows::Forms::Panel^ rightPanel;

        System::Windows::Forms::Label^ lblBrand;
        System::Windows::Forms::ListBox^ listProfiles;
        System::Windows::Forms::TextBox^ txtNewProfile;
        System::Windows::Forms::Button^ btnAddProfile;

        System::Windows::Forms::Label^ lblSelectedProfile;
        System::Windows::Forms::Button^ btnFreeze;
        System::Windows::Forms::Button^ btnThaw;

        System::Windows::Forms::Label^ lblInstruction;

        
        System::Windows::Forms::ComboBox^ cmbRunningApps;
        System::Windows::Forms::Button^ btnRefreshApps;
        System::Windows::Forms::Button^ btnAddApp;

        System::Windows::Forms::RichTextBox^ logBox;

        System::ComponentModel::Container^ components;
        Dictionary<String^, List<String^>^>^ profiles;

        void InitializeComponent(void)
        {
            this->components = gcnew System::ComponentModel::Container();
            this->Size = System::Drawing::Size(950, 600);
            this->Text = L"ContextFreezer v3.0 (Process Scanner)";
            this->StartPosition = FormStartPosition::CenterScreen;
            this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedSingle;
            this->MaximizeBox = false;
            this->BackColor = Color::FromArgb(32, 32, 32);
            this->ForeColor = Color::White;

         
            this->leftPanel = (gcnew System::Windows::Forms::Panel());
            this->rightPanel = (gcnew System::Windows::Forms::Panel());

           
            this->leftPanel->Dock = System::Windows::Forms::DockStyle::Left;
            this->leftPanel->Width = 260;
            this->leftPanel->BackColor = Color::FromArgb(40, 40, 40);
            this->leftPanel->Padding = System::Windows::Forms::Padding(15);

            this->lblBrand = (gcnew System::Windows::Forms::Label());
            this->lblBrand->Text = "PROFILLER";
            this->lblBrand->Font = (gcnew System::Drawing::Font(L"Segoe UI", 16, FontStyle::Bold));
            this->lblBrand->ForeColor = Color::White;
            this->lblBrand->Dock = DockStyle::Top;
            this->lblBrand->Height = 50;
            this->lblBrand->TextAlign = ContentAlignment::MiddleCenter;

            this->btnAddProfile = (gcnew System::Windows::Forms::Button());
            this->btnAddProfile->Text = "+ Yeni Profil";
            this->btnAddProfile->Height = 45;
            this->btnAddProfile->Dock = DockStyle::Bottom;
            this->btnAddProfile->FlatStyle = FlatStyle::Flat;
            this->btnAddProfile->BackColor = Color::FromArgb(46, 204, 113);
            this->btnAddProfile->ForeColor = Color::White;
            this->btnAddProfile->FlatAppearance->BorderSize = 0;
            this->btnAddProfile->Cursor = Cursors::Hand;
            this->btnAddProfile->Click += gcnew EventHandler(this, &MyForm::OnAddProfile);

            this->txtNewProfile = (gcnew System::Windows::Forms::TextBox());
            this->txtNewProfile->Text = "";
            this->txtNewProfile->Height = 30;
            this->txtNewProfile->Dock = DockStyle::Bottom;
            this->txtNewProfile->Font = (gcnew System::Drawing::Font(L"Segoe UI", 11));
            this->txtNewProfile->BackColor = Color::FromArgb(60, 60, 60);
            this->txtNewProfile->ForeColor = Color::White;
            this->txtNewProfile->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;

            Panel^ spacer = gcnew Panel();
            spacer->Height = 10;
            spacer->Dock = DockStyle::Bottom;
            spacer->BackColor = Color::Transparent;

            this->listProfiles = (gcnew System::Windows::Forms::ListBox());
            this->listProfiles->Dock = DockStyle::Fill;
            this->listProfiles->BackColor = Color::FromArgb(50, 50, 50);
            this->listProfiles->ForeColor = Color::WhiteSmoke;
            this->listProfiles->BorderStyle = System::Windows::Forms::BorderStyle::None;
            this->listProfiles->Font = (gcnew System::Drawing::Font(L"Segoe UI", 12));
            this->listProfiles->ItemHeight = 30;
            this->listProfiles->SelectedIndexChanged += gcnew EventHandler(this, &MyForm::OnProfileChanged);

            this->leftPanel->Controls->Add(this->listProfiles);
            this->leftPanel->Controls->Add(spacer);
            this->leftPanel->Controls->Add(this->txtNewProfile);
            this->leftPanel->Controls->Add(this->btnAddProfile);
            this->leftPanel->Controls->Add(this->lblBrand);

        
            this->rightPanel->Dock = System::Windows::Forms::DockStyle::Fill;
            this->rightPanel->BackColor = Color::FromArgb(32, 32, 32);
            this->rightPanel->Padding = System::Windows::Forms::Padding(40);

            this->lblSelectedProfile = (gcnew System::Windows::Forms::Label());
            this->lblSelectedProfile->Text = "Secili Profil: Yok";
            this->lblSelectedProfile->Font = (gcnew System::Drawing::Font(L"Segoe UI", 14));
            this->lblSelectedProfile->ForeColor = Color::LightGray;
            this->lblSelectedProfile->AutoSize = false;
            this->lblSelectedProfile->Size = System::Drawing::Size(500, 40);
            this->lblSelectedProfile->Location = System::Drawing::Point(40, 30);
            this->lblSelectedProfile->TextAlign = ContentAlignment::MiddleLeft;

            this->btnFreeze = (gcnew System::Windows::Forms::Button());
            this->btnFreeze->Text = "FREEZE (Dondur)";
            this->btnFreeze->Size = System::Drawing::Size(240, 60);
            this->btnFreeze->Location = System::Drawing::Point(40, 80);
            this->btnFreeze->FlatStyle = FlatStyle::Flat;
            this->btnFreeze->BackColor = Color::FromArgb(52, 152, 219);
            this->btnFreeze->ForeColor = Color::White;
            this->btnFreeze->FlatAppearance->BorderSize = 0;
            this->btnFreeze->Font = (gcnew System::Drawing::Font(L"Segoe UI", 12, FontStyle::Bold));
            this->btnFreeze->Cursor = Cursors::Hand;
            this->btnFreeze->Click += gcnew EventHandler(this, &MyForm::OnFreeze);

            this->btnThaw = (gcnew System::Windows::Forms::Button());
            this->btnThaw->Text = "THAW (Uyandir)";
            this->btnThaw->Size = System::Drawing::Size(240, 60);
            this->btnThaw->Location = System::Drawing::Point(300, 80);
            this->btnThaw->FlatStyle = FlatStyle::Flat;
            this->btnThaw->BackColor = Color::FromArgb(231, 76, 60);
            this->btnThaw->ForeColor = Color::White;
            this->btnThaw->FlatAppearance->BorderSize = 0;
            this->btnThaw->Font = (gcnew System::Drawing::Font(L"Segoe UI", 12, FontStyle::Bold));
            this->btnThaw->Cursor = Cursors::Hand;
            this->btnThaw->Click += gcnew EventHandler(this, &MyForm::OnThaw);

           
            this->lblInstruction = (gcnew System::Windows::Forms::Label());
            this->lblInstruction->Text = "Calisan Uygulamalardan Ekle:";
            this->lblInstruction->Location = System::Drawing::Point(40, 160);
            this->lblInstruction->AutoSize = true;
            this->lblInstruction->Font = (gcnew System::Drawing::Font(L"Segoe UI", 10));
            this->lblInstruction->ForeColor = Color::Gray;

            
            this->cmbRunningApps = (gcnew System::Windows::Forms::ComboBox());
            this->cmbRunningApps->Location = System::Drawing::Point(40, 190);
            this->cmbRunningApps->Size = System::Drawing::Size(350, 30);
            this->cmbRunningApps->Font = (gcnew System::Drawing::Font(L"Segoe UI", 11));
            this->cmbRunningApps->BackColor = Color::FromArgb(50, 50, 50);
            this->cmbRunningApps->ForeColor = Color::White;
            this->cmbRunningApps->DropDownStyle = ComboBoxStyle::DropDownList; 

            
            this->btnRefreshApps = (gcnew System::Windows::Forms::Button());
            this->btnRefreshApps->Text = "Yenile";
            this->btnRefreshApps->Location = System::Drawing::Point(400, 189);
            this->btnRefreshApps->Size = System::Drawing::Size(80, 32);
            this->btnRefreshApps->FlatStyle = FlatStyle::Flat;
            this->btnRefreshApps->BackColor = Color::FromArgb(70, 70, 70);
            this->btnRefreshApps->ForeColor = Color::White;
            this->btnRefreshApps->FlatAppearance->BorderSize = 0;
            this->btnRefreshApps->Click += gcnew EventHandler(this, &MyForm::OnRefreshApps);

           
            this->btnAddApp = (gcnew System::Windows::Forms::Button());
            this->btnAddApp->Text = "EKLE";
            this->btnAddApp->Location = System::Drawing::Point(490, 189);
            this->btnAddApp->Size = System::Drawing::Size(80, 32);
            this->btnAddApp->FlatStyle = FlatStyle::Flat;
            this->btnAddApp->BackColor = Color::FromArgb(46, 204, 113);
            this->btnAddApp->ForeColor = Color::White;
            this->btnAddApp->FlatAppearance->BorderSize = 0;
            this->btnAddApp->Font = (gcnew System::Drawing::Font(L"Segoe UI", 9, FontStyle::Bold));
            this->btnAddApp->Click += gcnew EventHandler(this, &MyForm::OnAddAppFromList);

            this->logBox = (gcnew System::Windows::Forms::RichTextBox());
            this->logBox->Location = System::Drawing::Point(40, 250);
            this->logBox->Size = System::Drawing::Size(530, 250);
            this->logBox->BackColor = Color::FromArgb(15, 15, 15);
            this->logBox->ForeColor = Color::FromArgb(0, 255, 0);
            this->logBox->BorderStyle = System::Windows::Forms::BorderStyle::None;
            this->logBox->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
            this->logBox->ReadOnly = true;
            this->logBox->Anchor = static_cast<AnchorStyles>(AnchorStyles::Top | AnchorStyles::Left | AnchorStyles::Right | AnchorStyles::Bottom);

            this->rightPanel->Controls->Add(this->logBox);
            this->rightPanel->Controls->Add(this->btnAddApp);
            this->rightPanel->Controls->Add(this->btnRefreshApps);
            this->rightPanel->Controls->Add(this->cmbRunningApps);
            this->rightPanel->Controls->Add(this->lblInstruction);
            this->rightPanel->Controls->Add(this->btnThaw);
            this->rightPanel->Controls->Add(this->btnFreeze);
            this->rightPanel->Controls->Add(this->lblSelectedProfile);

            this->Controls->Add(this->rightPanel);
            this->Controls->Add(this->leftPanel);
        }

        void InitializeData() {
            profiles = gcnew Dictionary<String^, List<String^>^>();

           
            List<String^>^ gameMode = gcnew List<String^>();
            
            gameMode->Add("SearchApp.exe");        
            gameMode->Add("OfficeClickToRun.exe");  
            gameMode->Add("OneDrive.exe");         
            gameMode->Add("PhoneExperienceHost.exe"); 
            gameMode->Add("Cortana.exe");           
            gameMode->Add("MicrosoftEdgeUpdate.exe");
            gameMode->Add("SkypeApp.exe");
            gameMode->Add("SkypeBackgroundHost.exe");
            gameMode->Add("Calculator.exe");       
            gameMode->Add("PhotosApp.exe");         
            gameMode->Add("YourPhone.exe");

            profiles["Oyun Modu (Hazir)"] = gameMode;
            UpdateProfileList();

          
            LoadRunningProcesses();
        }

        void LoadRunningProcesses() {
            cmbRunningApps->Items->Clear();
            std::vector<std::wstring> apps = GetRunningAppsNative();

            cmbRunningApps->Items->Add("-- Bir Uygulama Seciniz --");

            for (const auto& app : apps) {
                String^ mApp = msclr::interop::marshal_as<String^>(app);
                cmbRunningApps->Items->Add(mApp);
            }

            if (cmbRunningApps->Items->Count > 0)
                cmbRunningApps->SelectedIndex = 0;
        }

        void UpdateProfileList() {
            listProfiles->Items->Clear();
            for each (auto item in profiles) {
                listProfiles->Items->Add(item.Key);
            }
        }

        void Log(String^ msg) {
            logBox->AppendText(msg + "\n");
            logBox->ScrollToCaret();
        }

        void OnAddProfile(Object^ sender, EventArgs^ e) {
            String^ name = txtNewProfile->Text;
            if (!String::IsNullOrWhiteSpace(name) && !profiles->ContainsKey(name)) {
                profiles[name] = gcnew List<String^>();
                UpdateProfileList();
                txtNewProfile->Text = "";
            }
        }

        void OnProfileChanged(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem != nullptr) {
                String^ selected = listProfiles->SelectedItem->ToString();
                lblSelectedProfile->Text = "Secili Profil: " + selected;

                logBox->Clear();
                Log("--- '" + selected + "' Profilindeki Uygulamalar ---");
                for each (String ^ app in profiles[selected]) {
                    Log(">> " + app);
                }
            }
        }

       
        void OnRefreshApps(Object^ sender, EventArgs^ e) {
            LoadRunningProcesses();
            Log("[INFO] Calisan uygulamalar listesi yenilendi.");
        }

       
        void OnAddAppFromList(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem == nullptr) {
                MessageBox::Show("Lutfen once soldan bir profil secin!", "Hata", MessageBoxButtons::OK, MessageBoxIcon::Warning);
                return;
            }

            if (cmbRunningApps->SelectedIndex <= 0) return; 

            String^ appName = cmbRunningApps->SelectedItem->ToString();
            String^ currentProfile = listProfiles->SelectedItem->ToString();

            if (!profiles[currentProfile]->Contains(appName)) {
                profiles[currentProfile]->Add(appName);
                OnProfileChanged(nullptr, nullptr); 
                Log("[+] Eklendi: " + appName);
            }
            else {
                Log("[!] Bu uygulama zaten profilde var.");
            }
        }

        void OnFreeze(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem == nullptr) return;

            String^ profileName = listProfiles->SelectedItem->ToString();
            List<String^>^ apps = profiles[profileName];

            Log("\n[DONDURMA ISLEMI BASLATILIYOR...]");

            for each (String ^ app in apps) {
                std::wstring nativeName = msclr::interop::marshal_as<std::wstring>(app);
                std::vector<DWORD> pids = GetPidsNative(nativeName);

                if (pids.empty()) {

                }
                else {
                    for (DWORD pid : pids) {
                        SuspendNative(pid);
                        bool trimmed = TrimMemoryNative(pid);
                        Log("[*] " + app + " (PID " + pid + "): Donduruldu" + (trimmed ? " + RAM Silindi" : ""));
                    }
                }
            }
            Log("--- ISLEM TAMAMLANDI ---");
        }

        void OnThaw(Object^ sender, EventArgs^ e) {
            if (listProfiles->SelectedItem == nullptr) return;

            String^ profileName = listProfiles->SelectedItem->ToString();
            List<String^>^ apps = profiles[profileName];

            Log("\n[UYANDIRMA ISLEMI BASLATILIYOR...]");

            for each (String ^ app in apps) {
                std::wstring nativeName = msclr::interop::marshal_as<std::wstring>(app);
                std::vector<DWORD> pids = GetPidsNative(nativeName);

                for (DWORD pid : pids) {
                    ResumeNative(pid);
                    Log("[+] " + app + " (PID " + pid + "): Uyandirildi");
                }
            }
            Log("--- ISLEM TAMAMLANDI ---");
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