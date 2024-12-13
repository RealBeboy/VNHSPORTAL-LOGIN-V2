import tkinter as tk
from tkinter import ttk
import getpass
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Get the current directory where the script is located
script_dir = os.path.dirname(os.path.realpath(__file__))

def wait_for_page_load(driver):
    while driver.execute_script("return document.readyState;") != "complete":
        time.sleep(1)

def check_login(driver, url):
    try:
        driver.get(url)
        wait_for_page_load(driver)

        # Check for "no more sessions allowed" message
        no_more_sessions_xpath = "/html/body/section/div/div[2]/div"
        try:
            no_sessions = driver.find_element(By.XPATH, no_more_sessions_xpath)
            print(f"Account at {url}: No more sessions allowed.")
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
        print(f"Account at {url}: Login successful.")
        return True  # Login successful
    except Exception as e:
        print(f"Account at {url}: Error during login check: {e}")
        return False

def process_account(url, browser_choice):
    # Set up browser-specific options
    if browser_choice == "Brave":
        service = Service(os.path.join(script_dir, 'chromedriver.exe'))
        options = Options()
        options.binary_location = r"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    elif browser_choice == "Edge":
        service = Service(os.path.join(script_dir, 'msedgedriver.exe'))
        options = Options()
        options.binary_location = r"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"

    options.add_argument("--headless")  # Run in background
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    # Initialize the driver
    driver = webdriver.Chrome(service=service, options=options)

    login_success = False
    while not login_success:
        login_success = check_login(driver, url)

    # Wait 5 seconds before closing after successful login
    time.sleep(5)
    driver.quit()
    return url  # Return the URL of the successfully logged-in account

def login():
    username = username_entry.get()
    password = password_entry.get()
    browser_choice = browser_var.get()

    # Construct the URL using the user input
    url = f"http://vnhs.portal/login?&username={username}&password={password}"

    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = [executor.submit(process_account, url, browser_choice)]

        for future in as_completed(futures):
            url = future.result()
            print(f"Login successful for {url}, stopping other checks.")
            for future in futures:
                future.cancel()
            break

    # Add a message to the GUI after login
    success_label = ttk.Label(root, text="Login successful!", background="#D6EAF8", font=("Arial", 12))
    success_label.pack(pady=10)

# Create the main window
root = tk.Tk()
root.title("VNHS Portal Auto Login")
root.geometry("700x500")
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
browser_var = tk.StringVar(value="Brave")

browser_label = ttk.Label(root, text="Choose Browser:", background="#D6EAF8", font=("Arial", 12))
browser_label.pack(pady=5)

browser_dropdown = ttk.Combobox(root, textvariable=browser_var, state="readonly", font=("Arial", 12))
browser_dropdown['values'] = ("Brave", "Edge")
browser_dropdown.pack(pady=5)

# Button to trigger login
login_button = ttk.Button(root, text="Login", command=login)
login_button.pack(pady=20)

root.mainloop()
