import os
import subprocess
import requests
import zipfile
import telebot
import dns.resolver
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from database import init_db, add_user, log_scan, get_last_scans, get_user_info

BOT_TOKEN = ""
bot = telebot.TeleBot(BOT_TOKEN)

# هنا بتم تحميل الادوات في حالة تشغيل الكود لاول مرة على سيرفر جديد 
def ensure_tool(tool_name, download_url, exe_relative_path, extract_to="tools"):
    tool_path = os.path.join(extract_to, exe_relative_path)
    if os.path.exists(tool_path):
        return tool_path

    os.makedirs(extract_to, exist_ok=True)
    zip_path = os.path.join(extract_to, f"{tool_name}.zip")

    print(f"start download {tool_name}...")
    with requests.get(download_url, stream=True) as r:
        total_size = int(r.headers.get('content-length', 0))
        downloaded = 0
        chunk_size = 8192
        with open(zip_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    done_percent = (downloaded / total_size) * 100 if total_size else 0
                    print(f"download {tool_name}... {done_percent:.2f}% ({downloaded} from {total_size} Bt)", end='\r')
    print(f"{tool_name} Downloaded successfully ")

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)

    os.remove(zip_path)

    if not os.path.exists(tool_path):
        raise Exception(f"❌ {tool_name} not found after extraction.")

    return tool_path

tools_paths = {
    "subfinder": ensure_tool(
        "subfinder",
        "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_windows_amd64.zip",
        "subfinder.exe"
    ),
    "httpx": ensure_tool(
        "httpx",
        "https://github.com/projectdiscovery/httpx/releases/download/v1.7.1/httpx_1.7.1_windows_amd64.zip",
        "httpx.exe"
    ),
    "waybackurls": ensure_tool(
        "waybackurls",
        "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-windows-amd64-0.1.0.zip",
        "waybackurls.exe"
    ),
    "nmap": "nmap" # لازم يتنزل بشكل يدوي على السيرفر 
}

#دالة للتعامل مع المخرجات الطويلة بيرسلها بملف 
def send_long_result(bot, chat_id, text, limit=4000):
    if not text.strip():
        bot.send_message(chat_id, "⚠️ لم يتم العثور على نتائج.")
        return

    if len(text) > limit:
        filename = "output.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(text)
        with open(filename, "rb") as f:
            bot.send_document(chat_id, f)
        os.remove(filename)
    else:
        bot.send_message(chat_id, f"النتائج:\n{text}")

def main_menu():
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("Subdomains", callback_data="subdomains"))
    markup.add(InlineKeyboardButton("Live Domains", callback_data="live"))
    markup.add(InlineKeyboardButton("Scan Ports", callback_data="services"))
    markup.add(InlineKeyboardButton("Wayback URLs", callback_data="wayback"))
    markup.add(InlineKeyboardButton("DNS Records", callback_data="dns"))
    markup.add(InlineKeyboardButton("History", callback_data="history"))
    return markup

@bot.message_handler(commands=['start'])
def start(message):
    add_user(message.from_user.id, message.from_user.username, message.from_user.first_name)
    bot.send_message(message.chat.id,
                     """
- أهلاً وسهلا بك عزيزي المستخدم 🤖👋.
- هذا البوت عبارة عن تنفيذ لمشروع تخرج .
- يهدف البوت الى تسهيل تجربة المستخدم في استخدام تقنيات الفحص وجمع المعلومات .
------------------------------------------------------------
- طلاب المشروع :
- خالد نصار محمد جرادة 
- حسن مدحت حسن القدره 
- عبد الكريم رمزي ابو دقة
- رامي صافي
اختر نوع البحث من الاسفل 👇 .
للتواصل في حال واجهتك اي مشاكل [@lIKIlIll] .
""",
                     reply_markup=main_menu())
@bot.callback_query_handler(func=lambda call: call.data.startswith("history_"))
def show_history_result(call):
    index = int(call.data.split("_")[1])
    scans = get_last_scans(call.from_user.id)

    if index < len(scans):
        scan_type, result, date = scans[index] 
        send_long_result(bot, call.message.chat.id, f"📌 {scan_type} ({date})\n\n{result}")
    else:
        bot.send_message(call.message.chat.id, "⚠️ لم يتم العثور على النتيجة.")
@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    chat_id = call.message.chat.id

    if call.data == "subdomains":
        bot.register_next_step_handler_by_chat_id(chat_id, run_subdomain_enum)
        bot.send_message(chat_id, "قم بأرسال الدومين للبدأ")
    elif call.data == "live":
        bot.register_next_step_handler_by_chat_id(chat_id, run_filter_live)
        bot.send_message(chat_id, "قم بأرسال الدومين للبدأ")
    elif call.data == "services":
        bot.register_next_step_handler_by_chat_id(chat_id, run_services)
        bot.send_message(chat_id, "قم بأرسال الدومين للبدأ")
    elif call.data == "wayback":
        bot.register_next_step_handler_by_chat_id(chat_id, run_wayback)
        bot.send_message(chat_id, "قم بأرسال الدومين للبدأ")
    elif call.data == "dns":
        bot.register_next_step_handler_by_chat_id(chat_id, run_dns_records)
        bot.send_message(chat_id, "قم بأرسال الدومين للبدأ")
    elif call.data == "history":
        bot.register_next_step_handler_by_chat_id(chat_id, history)

def history(message):
    scans = get_last_scans(message.from_user.id)
    user_info = get_user_info(message.from_user.id)
    if not scans:
        bot.send_message(message.chat.id, "⚠️ لا يوجد عمليات محفوظة.")
        return
    msg = (
        f"👤 المستخدم: {user_info[1]} (@{user_info[0]})\n"
        f"📅 تاريخ الانضمام: {user_info[2]}\n"
        f"📊 عدد الفحوصات: {user_info[3]}\n\n"
        f"🗂 اختر العملية لعرض نتيجتها:"
    )
    markup = InlineKeyboardMarkup()
    for idx, scan in enumerate(scans):
        scan_type = scan[0]
        date = scan[2]
        markup.add(InlineKeyboardButton(f"{scan_type} ({date})", callback_data=f"history_{idx}"))

    bot.send_message(message.chat.id, msg, reply_markup=markup)

def run_subdomain_enum(message):
    domain = message.text.strip()
    if not domain:
        bot.send_message(message.chat.id, "⚠️ الدومين غير صالح.")
        return

    bot.send_message(message.chat.id, f"⏳ جارٍ جمع الدومينات الفرعية لـ: {domain}")
    output_dir = os.path.join("recon", domain, "subdomain")
    os.makedirs(output_dir, exist_ok=True)
    subfinder_file = os.path.join(output_dir, "subfinder.txt")
    merged_file = os.path.join(output_dir, "subdomains.txt")

    try:
        subprocess.run(
            [tools_paths['subfinder'], "-d", domain, "-silent", "-o", subfinder_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True
        )

        with open(subfinder_file, 'r', encoding='utf-8') as f:
            combined_list = f.read().splitlines()
        with open(merged_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(combined_list))

        display_text = "\n".join(combined_list)
        send_long_result(bot, message.chat.id, display_text)
        log_scan(message.from_user.id, f"Subdomains : {domain}", display_text)

    except Exception as e:
        bot.send_message(message.chat.id, f"⚠️ حدث خطأ:\n{e}")

def run_filter_live(message):
    domain = message.text.strip()
    subdomains_file = os.path.join("recon", domain, "subdomain", "subdomains.txt")
    live_file = os.path.join("recon", domain, "subdomain", "live.txt")

    if not os.path.isfile(subdomains_file):
        bot.send_message(message.chat.id, "⚠️ لم يتم العثور على ملف الدومينات الفرعية. يرجى تشغيل Subdomains أولاً.")
        return

    bot.send_message(message.chat.id, f"⏳ جارٍ فلترة الدومينات الحية لـ: {domain}")
    subprocess.run([tools_paths['httpx'], "-silent", "-l", subdomains_file, "-o", live_file],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

    with open(live_file, 'r', encoding='utf-8') as f:
        live_domains = f.read().splitlines()
    display_text = "\n".join(live_domains)
    send_long_result(bot, message.chat.id, display_text)
    log_scan(message.from_user.id, f"Live : {domain}", display_text)
def run_services(message):
    target = message.text.strip()
    if not target:
        bot.send_message(message.chat.id, "⚠️ الهدف غير صالح.")
        return
    bot.send_message(message.chat.id, f"⏳ جارٍ فحص الخدمات والمنافذ لـ: {target}")
    result = subprocess.check_output([tools_paths['nmap'], "-sV", target],
                                     text=True, timeout=120, shell=True)
    send_long_result(bot, message.chat.id, result)
    log_scan(message.from_user.id, f"nmap : {target}", result)
def run_wayback(message):
    domain = message.text.strip()
    if not domain:
        bot.send_message(message.chat.id, "⚠️ الدومين غير صالح.")
        return
    bot.send_message(message.chat.id, f"⏳ جارٍ جلب روابط Wayback لـ: {domain}")
    proc = subprocess.run([tools_paths['waybackurls']], input=domain,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    send_long_result(bot, message.chat.id, proc.stdout)
    log_scan(message.from_user.id, f"wayback : {domain}", proc.stdout)
def run_dns_records(message):
    domain = message.text.strip()
    if not domain:
        bot.send_message(message.chat.id, "⚠️ الدومين غير صالح.")
        return
    bot.send_message(message.chat.id, f"⏳ جارٍ جلب سجلات DNS لـ: {domain}")

    output = []
    for record_type in ["A", "CNAME", "TXT"]:
        output.append(f"=== {record_type} Record ===")
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                output.append(str(rdata))
        except dns.resolver.NoAnswer:
            output.append("لا توجد سجلات.")
        except dns.resolver.NXDOMAIN:
            output.append("الدومين غير موجود.")
        except Exception as e:
            output.append(f"خطأ أثناء جلب السجلات: {e}")
        output.append("")
    send_long_result(bot, message.chat.id, "\n".join(output))
    log_scan(message.from_user.id, f"dns : {domain}", output)

if __name__ == "__main__":
    init_db()
    print("Bot is running...")
    bot.infinity_polling()

