import re
from colorama import Fore, Style, init
import os

init()

ORANGE = "\033[38;5;214m"

def check_password(password):
    #rule 1: at least 8 characters
    if len(password) < 8:
        return 'Weak'
    
    #rule 2: at least 1 uppercase letter
    if not any(char.isupper() for char in password):
        return 'Weak'
    
    #rule 3: check for numbers
    if not any(char.isdigit() for char in password):
        return 'Moderate'
    
    if not any(re.search(r"[@#$%^&*()]", password) for char in password):
        return 'Moderate'
    
    return 'Strong'
    

    

user_password = input("Enter your password: ")

password_strength = check_password(user_password)

if password_strength == 'Weak':
    colored_strength = Fore.RED + password_strength + Style.RESET_ALL
elif password_strength == 'Moderate':
    colored_strength = ORANGE + password_strength + Style.RESET_ALL
elif password_strength == 'Strong': 
    colored_strength = Fore.GREEN + password_strength + Style.RESET_ALL

print(f"Your password strength is: {colored_strength}")

