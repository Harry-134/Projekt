import secrets
import string
import hashlib
import sys
import requests


def generate_password(length, use_uppercase=True, use_lowercase=True, 
                     use_digits=True, special_level="normal"):
    
    lowercase = string.ascii_lowercase if use_lowercase else ""
    uppercase = string.ascii_uppercase if use_uppercase else ""
    digits = string.digits if use_digits else ""
    
    if special_level == "simple":
        special = "!?#$%&@"
    elif special_level == "advanced":
        special = string.punctuation           
    else:  
        special = ""
    
    all_characters = lowercase + uppercase + digits + special
    
    if not all_characters:
        raise ValueError("Inga tecken valda - omöjligt att skapa lösenord")
    
    return ''.join(secrets.choice(all_characters) for _ in range(length))


def check_network_connection():
    try:
        requests.get("https://www.google.com", timeout=2)
        return True
    except Exception:
        return False


def check_password_hibp(password):
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        resp = requests.get(url, timeout=5, headers={"User-Agent": "PasswordChecker"})
        if resp.status_code != 200:
            return False
            
        for line in resp.text.splitlines():
            if not line:
                continue
            hash_suffix, count = line.split(":")
            if hash_suffix.strip().upper() == suffix:
                return True
        return False
        
    except Exception:
        return False


def generate_safe_password(length=12, special_level="normal", max_attempts=15):
    attempt = 0
    last_password = None
    
    while attempt < max_attempts:
        pwd = generate_password(
            length=length,
            special_level=special_level
        )
        last_password = pwd
        
        if check_password_hibp(pwd):
            attempt += 1
            continue
            
        return pwd, False 
    
    
    return last_password, True  

if __name__ == '__main__':

    # Verify OS to ensure compatibility
    current_os = platform.system()
    print(f"--- System Check: Running on {current_os} ---")

    # Check network; print blank and exit if no connection
    if not check_network_connection():
        sys.exit(1)

def main():
    print("\n=== Lösenordsgenerator ===\n")
    
    # Längd
    while True:
        try:
            length_input = input("Hur långt lösenord vill du ha? (8-32): ").strip()
            length = int(length_input)
            if 8 <= length <= 32:
                break
            print("Välj en längd mellan 8 och 32 tecken.\n")
        except ValueError:
            print("Skriv ett nummer tack.\n")

    # Specialtecken-nivå
    print("\nSpecialtecken nivå:")
    print("  1 = Enkla    (! ? # $ % & @)")
    print("  2 = Avancerade (alla vanliga specialtecken)")
    print("  0 = Inga specialtecken")
    
    while True:
        choice = input("Välj [0/1/2]: ").strip()
        if choice in ["0", "1", "2"]:
            special_map = {"0": "none", "1": "simple", "2": "advanced"}
            special_level = special_map[choice]
            break
        print("Välj 0, 1 eller 2 tack.\n")

    print("\nGenererar säkert lösenord", end="", flush=True)
    for _ in range(5):
        print(".", end="", flush=True)
    print()

    password, was_compromised = generate_safe_password(
        length=length,
        special_level=special_level,
        max_attempts=15
    )

    print("\n" + "=" * 60)
    print("Ditt lösenord:")
    print(f"  →  {password}  ←")
    print(f"  Längd: {len(password)} tecken")
    
    if was_compromised:
        print("  (Kunde inte hitta ett helt oanvänt lösenord efter flera försök)")
    else:
        print("Verkar inte finnas i kända läckor (HIBP)")
    print("=" * 60)
    
if __name__ == '__main__':
    if not check_network_connection():
        print("Ingen internet -> kan inte kolla HIBP")
        print("Genererar lösenord ändå (med secrets)...\n")
        
        password = generate_password(length=12, special_level="advanced")
        print("=" * 50)
        print(password)
        print("=" * 50)
        sys.exit(0)
    
    main()
