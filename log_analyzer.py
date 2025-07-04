from itertools import count
import time
import json
Clean_logs = []

with open ("generated_access.log","r") as f:
    for line in f.readlines():
        line = line.split()
        dic = {
        }
        dic["IP"] = line[0]
        dic["Data and Time"] = line[3].replace('[','')
        dic["Endpoint"] = line[6].replace('[','')
        dic["Method"] = line[5].replace('"','')
        dic["Status"] = line[8]
        dic["Size"] = line[9]
        dic["User"] = line[10].replace('"','')
        Clean_logs.append(dic)


def view_logs():
    print(json.dumps(Clean_logs,indent=4))


def bruteforce_attack():
    ac = False
    attempts = {}
    for i in Clean_logs:
        ip = i["IP"]
        if i["Endpoint"] == "/login" and i["Status"] == "401":
            if ip not in attempts:
                attempts[ip] = 1
            else:
                attempts[ip] += 1
    if attempts:     
        for ip, count in attempts.items():
            if count > 3:
                ac = True
                print(f"Suspicious IP: {ip} with {count} failed attempts")

    if ac == False:
        print("No Breach Found!")
        
def Suspicious_URL_Access():
    suspicious_paths = ["/admin", "/wp-login", "/phpmyadmin", "/.env", "/shell", "/config"]
    ac = False

    for i in Clean_logs:
        ip = i["IP"]
        if i["Endpoint"] in suspicious_paths:
            ac = True
            print(f"{ip} Tried to Access '{i['Endpoint']}' on {i['Data and Time']}")


    if ac == False:
        print("No Breach Found!")
        


def suspicious_Method():
    suspicious_methods = ["PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT"]
    ac = False
    for i in Clean_logs:
        ip = i["IP"]
        if i["Method"] in suspicious_methods:
            ac = True
            print(f"{ip} Tried Method {i['Method']} on Endpoint {i['Endpoint']}")

    if ac == False:
        print("No Breach Found!")



def FloodAttack():
    rqst = {}
    suspicious_found = False  

    for i in Clean_logs:
        ip = i["IP"]
        rqst[ip] = rqst.get(ip, 0) + 1

    for key, value in rqst.items():
        if value > 100:
            print(f"{key} Sent {value} Requests to the Server")
            suspicious_found = True

    if suspicious_found == False:
        print("No breach Found!")


def main():
    while True:
        print("Welcome to log Analyzer! Please Select Any One Operation: ")
        print("1. To Display the Server Logs.")
        print("2. To Analyze BruteForce Attack.")
        print("3. To Analyze Suspicious URL Access.")
        print("4. To Analyze Usage of Suspicious Methods.")
        print("5. To Detect Flood Attacks.")
        print("6. To Exit")
        choice = int(input("Enter your choice: "))
        print("Please wait", end="", flush=True)
        for i in range(3):
            print(".", end="", flush=True)
            time.sleep(1)
        print("\nProcessing Complete!")
        if choice == 1:
            view_logs()
        elif choice == 2:
            bruteforce_attack()
        elif choice == 3:
            Suspicious_URL_Access()
        elif choice == 4:
            suspicious_Method()
        elif choice == 5:
            FloodAttack()
        elif choice == 6:
            break
        else:
            print("Invalid Argument")
            break

main()
