import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import re
import os
import subprocess
import shutil
import stat
import time
import zipfile
import rarfile
import py7zr
import gzip
import base64
import urllib.request

whitelist = []

def select_folder():
    folder_selected = filedialog.askdirectory()
    folder_entry.delete(0, tk.END)
    folder_entry.insert(0, folder_selected)

def select_whitelist_file():
    file_selected = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    whitelist_entry.delete(0, tk.END)
    whitelist_entry.insert(0, file_selected)
    load_whitelist(file_selected)

def load_whitelist(file_path):
    global whitelist
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            whitelist = [line.strip() for line in file if line.strip()]
        update_whitelist_text()
    except Exception as e:
        print(f"Error loading whitelist: {e}")
        whitelist = []

def create_default_whitelist():
    default_whitelist_path = os.path.join(os.getcwd(), "whitelist.txt")
    if not os.path.exists(default_whitelist_path):
        with open(default_whitelist_path, 'w', encoding='utf-8') as file:
            file.write("# Add URLs to whitelist, one per line\n")
    return default_whitelist_path

def update_whitelist_text():
    whitelist_text_widget.config(state=tk.NORMAL)
    whitelist_text_widget.delete(1.0, tk.END)
    for url in whitelist:
        whitelist_text_widget.insert(tk.END, url + '\n')
    whitelist_text_widget.config(state=tk.DISABLED)

def extract_and_scan(file_path, scan_files):
    temp_dir = os.path.join(os.getcwd(), "temp_extracted")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    extracted_files = []

    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                extracted_files = [os.path.join(temp_dir, f) for f in zip_ref.namelist()]
        elif file_path.endswith('.rar'):
            with rarfile.RarFile(file_path, 'r') as rar_ref:
                rar_ref.extractall(temp_dir)
                extracted_files = [os.path.join(temp_dir, f) for f in rar_ref.namelist()]
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as z:
                z.extractall(path=temp_dir)
                extracted_files = [os.path.join(temp_dir, f) for f in z.getnames()]
        elif file_path.endswith('.gz'):
            with gzip.open(file_path, 'rb') as f_in:
                output_path = os.path.join(temp_dir, os.path.basename(file_path)[:-3])
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                extracted_files = [output_path]
        
        matches = scan_files(temp_dir)
        
        shutil.rmtree(temp_dir, onerror=on_rm_error)
        
        return matches
    
    except Exception as e:
        print(f"Error extracting {file_path}: {e}")
        return []

def scan_files(path):
    url_pattern = re.compile(r'https?://\S+')
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    base64_pattern = re.compile(r'(aHR[\w+/]+={0,2})')
    
    matches = []
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith(('.zip', '.rar', '.7z', '.gz')):
                matches.extend(extract_and_scan(file_path, scan_files))
            else:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        urls = url_pattern.findall(content)
                        ips = ip_pattern.findall(content)
                        base64s = base64_pattern.findall(content)
                        filtered_urls = [url for url in urls if not any(whitelisted in url for whitelisted in whitelist)]
                        if filtered_urls or ips or base64s:
                            matches.append((file_path, filtered_urls, ips, base64s))
                except UnicodeDecodeError:
                    print(f"Skipping binary file: {file_path}")
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
    
    return matches

def download_github_repo(url, download_path):
    try:
        subprocess.run(['git', 'clone', url, download_path], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        return False

def on_rm_error(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def scan():
    path = folder_entry.get()
    github_url = github_entry.get()
    
    if not path and not github_url:
        messagebox.showerror("Error", "Please provide a folder path or GitHub URL.")
        return
    
    if github_url:
        path = os.path.join(os.getcwd(), "temp_repo")
        if not download_github_repo(github_url, path):
            messagebox.showerror("Error", "Failed to download GitHub repository.")
            return
    
    results = scan_files(path)
    
    if github_url:
        # delete temp repo
        time.sleep(1)
        try:
            shutil.rmtree(path, onerror=on_rm_error)
        except Exception as e:
            print(f"Error removing temporary repo folder: {e}")
    
    if results:
        result_text_widget.config(state=tk.NORMAL)
        result_text_widget.delete(1.0, tk.END)
        
        for res in results:
            result_text_widget.insert(tk.END, f"File: {res[0]}\n", "normal")
            
            if res[1]:
                result_text_widget.insert(tk.END, "URLs:\n", "normal")
                for url in res[1]:
                    result_text_widget.insert(tk.END, f'"{url}"\n', "normal")
            else:
                result_text_widget.insert(tk.END, "URLs: []\n", "normal")
            
            if res[2]:
                result_text_widget.insert(tk.END, "IPs:\n", "normal")
                for ip in res[2]:
                    result_text_widget.insert(tk.END, f'"{ip}"\n', "normal")
            else:
                result_text_widget.insert(tk.END, "IPs: []\n", "normal")
            
            if res[3]:
                result_text_widget.insert(tk.END, "BASE64:\n", "normal")
                for b64 in res[3]:
                    try:
                        decoded_text = base64.b64decode(b64).decode('utf-8')
                        result_text_widget.insert(tk.END, f'BASE64 FOUND -> "{b64}"\n', "base64")
                        result_text_widget.insert(tk.END, f'BASE64 DECODED -> "{decoded_text}"\n', "decoded")
                    except Exception as e:
                        result_text_widget.insert(tk.END, f'BASE64 FOUND -> "{b64}" (Decoding failed)\n', "base64")
            else:
                result_text_widget.insert(tk.END, "BASE64: []\n", "normal")
            
            result_text_widget.insert(tk.END, "\n", "normal")
        
        result_text_widget.config(state=tk.DISABLED)
        
        # logs.txt
        with open("logs.txt", "w", encoding='utf-8') as log_file:
            for res in results:
                log_file.write(f"File: {res[0]}\n")
                log_file.write("URLs:\n" + ("\n".join([f'\"{url}\"' for url in res[1]]) if res[1] else "[]") + "\n")
                log_file.write("IPs:\n" + ("\n".join([f'\"{ip}\"' for ip in res[2]]) if res[2] else "[]") + "\n")
                log_file.write("BASE64:\n")
                for b64 in res[3]:
                    try:
                        decoded_text = base64.b64decode(b64).decode('utf-8')
                        log_file.write(f'BASE64 FOUND -> "{b64}"\n')
                        log_file.write(f'BASE64 DECODED -> "{decoded_text}"\n')
                    except Exception as e:
                        log_file.write(f'BASE64 FOUND -> "{b64}" (Decoding failed)\n')
                log_file.write("\n")
    else:
        messagebox.showinfo("Scan Results", "No URLs, IP addresses, or base64 strings found.")
        with open("logs.txt", "w", encoding='utf-8') as log_file:
            log_file.write("No URLs, IP addresses, or base64 strings found.\n")


def download_azure_theme():
    url = "https://github.com/rdbende/Azure-ttk-theme/archive/refs/heads/main.zip"
    file_path = "azure_theme.zip"
    extract_path = "azure_theme"
    
    try:
        print(f"Downloading theme from {url}...")
        urllib.request.urlretrieve(url, file_path)
        print(f"Downloaded to {file_path}")
        
        print(f"Extracting {file_path}...")
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        print(f"Extracted to {extract_path}")
        
        base_dir = os.path.join(extract_path, "Azure-ttk-theme-main")
        azure_tcl_path = os.path.join(base_dir, "azure.tcl")
        theme_dir = os.path.join(base_dir, "theme")
        
        if os.path.exists(azure_tcl_path):
            shutil.move(azure_tcl_path, os.getcwd())
            print("azure.tcl moved successfully.")
        else:
            print(f"azure.tcl not found in {base_dir}")
        
        if os.path.exists(theme_dir):
            shutil.move(theme_dir, os.getcwd())
            print("Theme directory moved successfully.")
        else:
            print(f"Theme directory not found in {base_dir}")
        
        os.remove(file_path)
        shutil.rmtree(extract_path)
        print("Temporary files removed successfully.")
        
    except Exception as e:
        print(f"Failed to download and extract Azure theme: {e}")



app = tk.Tk()
app.title("URL and IP Scanner")

# ttk
style = ttk.Style(app)
style.configure('TLabel', font=('Helvetica', 12))
style.configure('TButton', font=('Helvetica', 12), padding=6)
style.configure('TEntry', font=('Helvetica', 12), padding=6)
style.configure('TText', font=('Helvetica', 12))

# Azure theme
download_azure_theme()
try:
    app.tk.call("source", "azure.tcl")
    app.tk.call("set_theme", "light")
except tk.TclError as e:
    messagebox.showerror("Theme Error", f"Couldn't load theme file: {e}")
    print(f"Couldn't load theme file: {e}")

# GUI
ttk.Label(app, text="Folder Path:").grid(row=0, column=0, padx=10, pady=10)
folder_entry = ttk.Entry(app, width=50)
folder_entry.grid(row=0, column=1, padx=10, pady=10)
ttk.Button(app, text="Browse", command=select_folder).grid(row=0, column=2, padx=10, pady=10, sticky='w')

ttk.Label(app, text="GitHub URL:").grid(row=1, column=0, padx=10, pady=10)
github_entry = ttk.Entry(app, width=50)
github_entry.grid(row=1, column=1, padx=10, pady=10)

ttk.Label(app, text="Whitelist File:").grid(row=2, column=0, padx=10, pady=10)
whitelist_entry = ttk.Entry(app, width=50)
whitelist_entry.grid(row=2, column=1, padx=10, pady=10)
ttk.Button(app, text="Browse", command=select_whitelist_file).grid(row=2, column=2, padx=10, pady=10, sticky='w')
ttk.Button(app, text="Reload", command=lambda: load_whitelist(whitelist_entry.get())).grid(row=2, column=3, padx=10, pady=10, sticky='w')

ttk.Button(app, text="Scan", command=scan).grid(row=3, column=1, padx=10, pady=10)

whitelist_frame = ttk.Frame(app)
whitelist_frame.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky='nsew')

whitelist_text_widget = tk.Text(whitelist_frame, wrap='word', height=5, width=80)
whitelist_text_widget.config(state=tk.DISABLED)
whitelist_text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

whitelist_scrollbar = ttk.Scrollbar(whitelist_frame, command=whitelist_text_widget.yview)
whitelist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

whitelist_text_widget['yscrollcommand'] = whitelist_scrollbar.set

result_frame = ttk.Frame(app)
result_frame.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky='nsew')

result_text_widget = tk.Text(result_frame, wrap='word', height=20, width=80)
result_text_widget.config(state=tk.DISABLED)
result_text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

result_scrollbar = ttk.Scrollbar(result_frame, command=result_text_widget.yview)
result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

result_text_widget['yscrollcommand'] = result_scrollbar.set

result_text_widget.tag_config('base64', foreground='red', font=('Helvetica', 10, 'bold'))
result_text_widget.tag_config('decoded', foreground='green', font=('Helvetica', 10, 'bold'))
result_text_widget.tag_config('normal', foreground='black', font=('Helvetica', 10))

app.grid_rowconfigure(5, weight=1)
app.grid_columnconfigure(1, weight=1)

default_whitelist_path = create_default_whitelist()
load_whitelist(default_whitelist_path)
whitelist_entry.insert(0, default_whitelist_path)

app.mainloop()