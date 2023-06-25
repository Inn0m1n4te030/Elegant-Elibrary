import gspread
from oauth2client.service_account import ServiceAccountCredentials
from pprint import pprint as pp
scope = ["https://spreadsheets.google.com/feeds",'https://www.googleapis.com/auth/spreadsheets',"https://www.googleapis.com/auth/drive.file","https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name("creds.json",scope)
client = gspread.authorize(creds)
sheet = client.open("SQLI Alert").sheet1 

#Sending SQLI Alerts to Google Sheet
def send_to_sheet(ip,inputString,cate,ts):
    appendRow = [ip,inputString,cate,ts]
    sheet.append_row(appendRow)