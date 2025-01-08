import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import getpass
import time
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import subprocess

# Get the current directory where the script is located
script_dir = os.path.dirname(os.path.realpath(__file__))
config_path = os.path.join(script_dir, "browser_config.json")

def load_config():
    if os.path.exists(config_path):
        with open(config_path, "r") as file:
            return json.load(file)
    return {}

def save_config(config):
    with open(config_path, "w") as file:
        json.dump(config, file, indent=4)

# Load existing configuration
config = load_config()

def wait_for_page_load(driver):
    while driver.execute_script("return document.readyState;") != "complete":
        time.sleep(1)

def check_login(driver, url, username):  # Added username parameter
    try:
        driver.get(url)
        wait_for_page_load(driver)

        # Check for "no more sessions allowed" message
        no_more_sessions_xpath = "/html/body/section/div/div[2]/div"
        try:
            no_sessions = driver.find_element(By.XPATH, no_more_sessions_xpath)
            print(f"Account at {username}: No more sessions allowed.")
            driver.refresh()  # Refresh if this message appears
            time.sleep(0.1)
            return False  # Login failed, retry after refresh
        except:
            pass

        # Check for login success message
        login_xpath = "/html/body/div/div/form/div/input"
        login_message = WebDriverWait(driver, 0.1).until(
            EC.presence_of_element_located((By.XPATH, login_xpath))
        )
        print(f"Account at {username}: Login successful.")
        return True  # Login successful
    except Exception as e:
        print(f"Account at {username}: Error during login check: {e}")
        return False

def process_account(url, browser_choice, username):  # Added username parameter
    binary_path = config.get(browser_choice)

    if not binary_path:
        raise ValueError(f"Binary location for {browser_choice} is not set.")

    # Set up browser-specific options
    service = Service(os.path.join(script_dir, 'chromedriver.exe')) if browser_choice == "Brave/Chrome" else Service(os.path.join(script_dir, 'msedgedriver.exe'))
    options = Options()
    options.binary_location = binary_path

    options.add_argument("--headless")  # Run in background
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    # Initialize the driver
    driver = webdriver.Chrome(service=service, options=options)

    login_success = False
    while not login_success:
        login_success = check_login(driver, url, username)  # Pass username

    # Wait 5 seconds before closing after successful login
    time.sleep(5)
    driver.quit()
    return url  # Return the URL of the successfully logged-in account

def get_connected_ssid():
    """
    Retrieves the SSID of the currently connected Wi-Fi network.
    Works on Windows using the 'netsh' command.
    """
    try:
        output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], text=True)
        for line in output.splitlines():
            if "SSID" in line:
                return line.split(":", 1)[1].strip()
    except Exception as e:
        print(f"Error fetching SSID: {e}")
    return None

def login():
    ssid = get_connected_ssid()
    if ssid != "PLDTHOMEFIBR74401":
        messagebox.showerror("Connection Error", "Make sure you are connected to 'VNHS PORTAL'.")
        return

    username = username_entry.get()
    password = password_entry.get()
    browser_choice = browser_var.get()

    if browser_choice not in config:
        messagebox.showerror("Error", f"Binary location for {browser_choice} is not set.")
        return

    # Construct the URL using the user input
    url = f"http://vnhs.portal/login?&username={username}&password={password}"

    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = [executor.submit(process_account, url, browser_choice, username)]  # Pass username

        for future in as_completed(futures):
            url = future.result()
            print(f"Login successful for {username}, stopping other checks.")
            for future in futures:
                future.cancel()
            break

    # Add a message to the GUI after login
    success_label = ttk.Label(root, text="Login successful!", background="#D6EAF8", font=("Arial", 12))
    success_label.pack(pady=10)

def set_binary():
    browser_choice = browser_var.get()
    binary_path = filedialog.askopenfilename(title=f"Select binary for {browser_choice}", filetypes=[("Executables", "*.exe")])

    if binary_path:
        config[browser_choice] = binary_path
        save_config(config)
        binary_label_var.set(f"Binary Location: {binary_path}")
        messagebox.showinfo("Success", f"Binary location for {browser_choice} has been set.")

def reset_config():
    if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset the configuration?"):
        if os.path.exists(config_path):
            os.remove(config_path)
        config.clear()
        binary_label_var.set("Binary Location: Not Set")
        messagebox.showinfo("Reset", "Configuration has been reset.")

def update_binary_label(*args):
    browser_choice = browser_var.get()
    binary_label_var.set(f"Binary Location: {config.get(browser_choice, 'Not Set')}")

# Create the main window
root = tk.Tk()
root.title("VNHS Portal Auto Login")
root.geometry("700x600")
root.configure(bg="#D6EAF8")  # Light blue background

# Header label
header_label = ttk.Label(root, text="Welcome to VNHS Portal", font=("Arial", 16, "bold"), background="#D6EAF8")
header_label.pack(pady=10)

# Label for username
username_label = ttk.Label(root, text="Username:", background="#D6EAF8", font=("Arial", 12))
username_label.pack(pady=5)

# Entry field for username
username_entry = ttk.Entry(root, font=("Arial", 12))
username_entry.pack(pady=5)

# Label for password (hidden)
password_label = ttk.Label(root, text="Password:", background="#D6EAF8", font=("Arial", 12))
password_label.pack(pady=5)

# Entry field for password (using getpass for security)
password_entry = ttk.Entry(root, show="*", font=("Arial", 12))  # Asterisks hide the password
password_entry.pack(pady=5)

# Dropdown for browser choice
browser_var = tk.StringVar(value="Brave/Chrome")
browser_var.trace("w", update_binary_label)

browser_label = ttk.Label(root, text="Choose Browser:", background="#D6EAF8", font=("Arial", 12))
browser_label.pack(pady=5)

browser_dropdown = ttk.Combobox(root, textvariable=browser_var, state="readonly", font=("Arial", 12))
browser_dropdown['values'] = ("Brave/Chrome", "Edge")
browser_dropdown.pack(pady=5)

# Binary location label
binary_label_var = tk.StringVar(value="Binary Location: Not Set")
binary_label = ttk.Label(root, textvariable=binary_label_var, background="#D6EAF8", font=("Arial", 12))
binary_label.pack(pady=5)

# Button to set binary location
set_binary_button = ttk.Button(root, text="Set Binary Location", command=set_binary)
set_binary_button.pack(pady=10)

# Button to reset configuration
reset_button = ttk.Button(root, text="Reset Configuration", command=reset_config)
reset_button.pack(pady=10)

# Button to trigger login
login_button = ttk.Button(root, text="Login", command=login)
login_button.pack(pady=20)

# Initialize binary label based on config
update_binary_label()

root.mainloop()