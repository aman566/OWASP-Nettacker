#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    """
    keep all messages in ps

    Returns:
        all messages in JSON
    """
    return {
        "scan_started": "د نیټیکر انجنیر پیل شو",
        "options": "پیډون nettacker.py [اختیارونه]",
        "help_menu": "د Nettacker د مرستې مینو ښودل",
        "license": "مهرباني وکړئ لايسنس او ​​تړونونه وګورئ https://github.com/zdresearch/OWASP-Nettacker",
        "engine": "انجن",
        "engine_input": "د انجن د وسیلو اختیارونه",
        "select_language": "یوه ژبه وټاکئ {0}",
        "range": "په ټولو برخو کې د آی.پی.سی سکین کړئ",
        "subdomains": "فرعي ډومینونه ومومئ او سکین کړئ",
        "thread_number_connections": "د کوربه توکیو لپاره د تار شمیره",
        "thread_number_hosts": "د سکین میزونو لپاره د تار شمیره",
        "save_logs": "ټولې دوتنې په فایل کې خوندي کړئ (results.txt، results.html، result.json)",
        "target": "هدف",
        "target_input": "د نښه کولو انتخابونه",
        "target_list": 'د هدفونو لیست، د "،" سره جلا کول',
        "read_target": "د دوتنې څخه هدف (ه) ولولئ",
        "scan_method_options": "د سکین طریقې اختیارونه",
        "choose_scan_method": "د سکین طریقه غوره کړه {0}",
        "exclude_scan_method": "{0} لرې کولو لپاره د سکین طریقه وټاکئ",
        "username_list": 'د کارن نوموونکي لیست، د "،" سره جلا',
        "username_from_file": "د دوتنې څخه کارن نوم",
        "password_seperator": 'د پټنوم (لسټ) لیست، د "،" سره جلا کړئ',
        "read_passwords": "د دوتنې څخه پټنوم (پوسټ) ولولئ",
        "port_seperator": 'د بندرونو لیست، د "،" سره جلا کول',
        "time_to_sleep": "د هرې غوښتنې په منځ کې د خوب کولو وخت",
        "error_target": "هدف یا هدف مشخص کولی نشی",
        "error_target_file": "نشی ټاکل شوی هدفونه، د فایل پرانستلو توان نلري: {0}",
        "thread_number_warning": "دا غوره ده چې د موضوع شمیره د 100 څخه کمه وي، BTW مونږ دوام کوو ...",
        "set_timeout": "د {0} ثانیو لپاره وخت وخت ټاکئ، دا خورا لوی دی، نه دا؟ په هغه لاره چې موږ دوام کوو ...",
        "scan_module_not_found": "دا سکین ماډول [{0}] ونه موندل شو!",
        "error_exclude_all": "تاسو د سکین ټولې میتودونه نه شي کولی",
        "exclude_module_error": "د {0} ماډل مو غوره کړی چې و نه موندل شي.",
        "method_inputs": "د میتودونو ځایونو ته ورننوتئ، مثال: ftp_brute_users = ا"
        "زموینه، اداره او د فایل بکس_passwds = لوست_ نوم_میل: /tmp/pass.txt&ftp_brute_port=21",
        "error_reading_file": "د دوتنه فایل نه شی کولی",
        "error_username": "د کارن نوم نه دی مشخصولی، د فایل پرانستلو توان نلري: {0}",
        "found": "{0} وموندل شو! ({1}: {2})",
        "error_password_file": "تایید نشی کولی پټنوم (s)، د فایل پرانستلو توان نلري: {0}",
        "file_write_error": 'دوتنه "{0}" لیکل شوی نه دی!',
        "scan_method_select": "مهرباني وکړئ د خپل سکین میتود غوره کړئ!",
        "remove_temp": "د طلوع فایلونو لیرې کول!",
        "sorting_results": "د پایلو ترتیبول!",
        "done": "ترسره شوی!",
        "start_attack": "{0}، {1} د {2} په برید پیل کوي",
        "module_not_available": 'دا موډول "{0}" شتون نلري',
        "error_platform": "له بده مرغه د دې سافټویر نسخه یواځې د لینوکس / اوکسکس / کړکۍ پرمخ وړل کیدی شي.",
        "python_version_error": "ستاسو د پیډون نسخه ملاتړ ندی شوی!",
        "skip_duplicate_target": "د نقل نقل هدف (ځینې فرعي ډومینونه / ډومینونه هم یو شان IP او Ranges لري)",
        "unknown_target": "د هدف نامعلوم ډول [{0}]",
        "checking_range": "د {0} سلسله ګوري ...",
        "checking": "وګورئ ...",
        "HOST": "HOST",
        "USERNAME": "USERNAME",
        "PASSWORD": "رمز",
        "PORT": "PORT",
        "TYPE": "TYPE",
        "DESCRIPTION": "DESCRIPTION",
        "verbose_level": "د فعالو موډ کچه (0-5) (اصلي 0)",
        "software_version": "د ساوتري نسخه ښودل",
        "check_updates": "اوسمهال وګوره",
        "outgoing_proxy": "بهرنی اړیکو پراکسي (جرابې). د مثال مثالونه:"
        " 127.0.0.1:9050، جرابې: //127.0.0.1: 9050 جرکۍ 5: //127.0.0.1: 9050 یا جرابې 4: جرابې:"
        " //127.0.0.1: 9050، تصدیق: جراب: // // کارن-نوم: پاسورډ 127.0.0.1، socks4: "
        "// کارن-نوم: password@127.0.0.1، socks5: // کارن-نوم: پاسورډ@127.0.0.1",
        "valid_socks_address": "مهرباني وکړئ د سم جرابې پته او پورتنه داخل کړئ. د مثال مثالونه: "
        "127.0.0.1:9050، جرابې: //127.0.0.1: 9050، جرکۍ 5: //127.0.0.1: 9050 یا جرابې "
        "4: جرابې: //127.0.0.1: 9050، تصدیق: جراب: // // کارن-نوم: پاسورډ @ 127.0.0.1،"
        " socks4: // کارن-نوم: password@127.0.0.1، socks5: // کارن-نوم: پاسورډ@127.0.0.1",
        "connection_retries": "کله چې د ارتباط وخت (default 3",
        "ftp_connection_timeout": "د FTP اړیکه د {0}: {1} وخت نیسي، غصب کول {2}: {3}",
        "login_successful": "په بریالیتوب سره نښلول!",
        "login_list_error": "په بریالیتوب سره نښلول، د لیست کمیسون لپاره اجازه ورکړل شوه!",
        "ftp_connection_failed": "د FTP اړیکه د {0}: {1} ناکامه"
        " شوه، د بشپړ مرحلې [پروسیجر {2} {3}] لیرې کول! راتلونکی ګام ته لاړ شه",
        "input_target_error": "{0} ماډل لپاره د انټرنیټ موخه باید DOMAIN، HTTP یا SINGLE_IPv4 وي، ځنډول {1}",
        "user_pass_found": "کارن: {0} پاسورډ: {1} میزبان: {2} بندر: {3} وموندل شو!",
        "file_listing_error": "(د لیست فلمونو لپاره هیڅ ډول اجازه نشته)",
        "trying_message": "{0} {1} د {2} {4}: {5} ({6}) په بهیر کې {2} هڅه کوي",
        "smtp_connection_timeout": "د SMTP نښلول {0}: {1} وخت نیسي، غصب کول {2}: {3}",
        "smtp_connection_failed": "د SMTP پیوستون ته {0}: {1} ناکام شو،"
        " د بشپړ مرحله [پروسیجر {2} {3}] لرې کولو! راتلونکی ګام ته لاړ شه",
        "ssh_connection_timeout": "د SSH کنکشن {0}: {1} وخت نیسي، ځپلي {2}: {3}",
        "ssh_connection_failed": "د SSH کنکشن {0}: {1} ناکامه شوه، د بشپړ مرحله [پروسیجر "
        "{2} {3}] لغوه کول! راتلونکی ګام ته لاړ شه",
        "port/type": "{0} / {1}",
        "port_found": "کوربه: {0} بندر: {1} ({2}) وموندل شو!",
        "target_submitted": "هدف {0} ورکړل شوی!",
        "current_version": "تاسو د OWASP نټیکریر نسخه چلول {0} {1} {2} {6} د کوډ نوم {3} {4} {5}",
        "feature_unavailable": "دا فیچر لا تر اوسه شتون"
        ' نلري! مهرباني وکړئ "ګټ کلون https://github.com/zdresearch/OWASP-Nettacker.git"'
        ' یا "پایپ لاین" نصب کړئ - د OWASP-Nettacker وروستی نسخه ترلاسه کولو لپاره.',
        "available_graph": "د ټولو فعالیتونو او معلوماتو گراف"
        " جوړ کړئ، تاسو باید د HTML محصول کاروئ. موجود ګرافونه: {0}",
        "graph_output": "د ګراف خاصیت کارولو لپاره ستاسو "
        'د پیداوار فایل نوم باید د ".html" یا ".htm" سره پای ته ورسیږي!',
        "build_graph": "ګراف جوړول ...",
        "finish_build_graph": "د ودانولو پای ګراف!",
        "pentest_graphs": "د ننوتلو معاینه ګرافونه",
        "graph_message": "دا ګراف د OWASP Nettacker لخوا "
        "جوړ شوی. په ګراف کې د ماډل فعالیتونه، د شبکې نقشه او حساس معلومات شامل"
        " دي، مهرباني وکړئ دا دوتنه د هر چا سره شریک کړئ که دا باوري نه وي.",
        "nettacker_report": "د OWASP نټیکاکر راپور",
        "nettacker_version_details": "د سافټویر توضیحات: OWASP نټیکیرر نسخه {0} [{1}] په {2}",
        "no_open_ports": "هیڅ پرانیستي بندر ونه موندل شو!",
        "no_user_passwords": "هیڅ کارن / پاسورډ ونه موندل شو!",
        "loaded_modules": "{0} ماډلونه پورته شوي ...",
        "graph_module_404": "د دې ګراف ماډل ونه موندل شو: {0}",
        "graph_module_unavailable": 'د دې ګراف ماډول "{0}" شتون نلري',
        "ping_before_scan": "د کوربه سکین مخکې مخکې",
        "skipping_target": "د ټول هدف ضایع کول {0} او د سکینګ طریقه"
        " {1} ځکه چې د کانګینګ مخکې مخکې اسکین سم دی او دا ځواب نه دی ورکړ شوی!",
        "not_last_version": "تاسو د OWASP Nettacker وروستنۍ نسخه نه کاروئ، مهرباني وکړئ تازه کړئ.",
        "cannot_update": "د اوسمهال لپاره ندی لیدلی، مهرباني وکړئ خپل انټرنټ کنټرول وګورئ.",
        "last_version": "تاسو د OWASP Nettacker وروستنۍ نسخه کاروئ ...",
        "directoy_listing": "د لارښوونې لیست په {0} کې وموندل شو",
        "insert_port_message": "مهرباني وکړئ د -g یا -methods- د آر ایل پهځای د args switch له لارې بندر داخل کړئ",
        "http_connection_timeout": "http اړیکې {0} وخت",
        "wizard_mode": "د جادوگر اکر پېل کړئ",
        "directory_file_404": "هیڅ لارښود یا فایل د {1} بندر {1} لپاره نه موندل شوی",
        "open_error": "د خلاصولو توان نلري {0}",
        "dir_scan_get": "dir_scan_http_method ارزښت باید GET یا HEAD وي، د GET لپاره ډیزاین ترتیب کړئ.",
        "list_methods": "ټول میتودونه لیست کړئ",
        "module_args_error": "نشي کولی د ماډول ارقام ترلاسه کړي",
        "trying_process": "د {0} {1} په بهیر کې {2} د {3} په {4} ({5}) کې هڅه کوي",
        "domain_found": "ډومین وموندل شو: {0}",
        "TIME": "TIME",
        "CATEGORY": "CATEGORY",
        "module_pattern_404": "د {0} نمونې سره هیڅ ماډل ونه موندل شي!",
        "enter_default": "مهرباني وکړئ {0} | اصلي [{1}]>",
        "enter_choices_default": "مهرباني وکړئ {0} | انتخابونه [{1}] | Default [{2}]>",
        "all_targets": "اهداف",
        "all_thread_numbers": "د موضوع شمېره",
        "out_file": "د فایل فایل نوم",
        "all_scan_methods": "د سکین طریقې",
        "all_scan_methods_exclude": "د جلا کولو لپاره سکین طریقه",
        "all_usernames": "د کارن نومونه",
        "all_passwords": "شفرونه",
        "timeout_seconds": "د وختونو ثانوي",
        "all_ports": "د بندر شمیره",
        "all_verbose_level": "د منلو کچه",
        "all_socks_proxy": "جرابې پراکسي",
        "retries_number": "د بیرته ترلاسه کولو شمیره",
        "graph": "يوه ګراف",
        "subdomain_found": "فرعي ماډل وموندل شو: {0}",
        "select_profile": "پېژندڅېره {{} غوره کړه",
        "profile_404": 'پروفائل "{0}" ونه موندل شو!',
        "waiting": "د {0} انتظار",
        "vulnerable": "{0} ته زیان رسونکي",
        "target_vulnerable": "هدف {0}: {1} د {2} زیان منونکی دی!",
        "no_vulnerability_found": "هیڅ زیان مننه نه موندل کیږي! ({0})",
        "Method": "میتود",
        "API": "API",
        "API_options": "د API اختیارونه",
        "start_API": "د API خدمت پیل کړئ",
        "API_host": "د API کوربه پته",
        "API_port": "د API پورتنۍ شمیره",
        "API_debug": "د API ډبګ موډ",
        "API_access_key": "د API لاسرسی کیلي",
        "white_list_API": "یوازې د سپینې لیست الوتکې ته اجازه ورکړئ چې API سره ونښلول شي",
        "define_whie_list": "د سپینې لیست میزان تعریف کړئ، "
        "سره جلا کړئ، (مثالونه: 127.0.0.1، 192.168.0.1/24، 10.0.0.1-10.0.0.255)",
        "gen_API_access_log": "د API لاسرسی پیدا کړئ",
        "API_access_log_file": "د API لاسرغاړه دوتنه نوم",
        "API_port_int": "د API بندر باید یو عامل وي!",
        "unknown_ip_input": "نامعلوم ډول ډول ډولونه، منل شوي ډولونه SINGLE_IPv4، RANGE_IPv4، CIDR_IPv4 دي",
        "API_key": "* API Key: {0}",
        "ports_int": "بندرونه باید حتمي وي! (لکه 80 || 80،1080 || 80،1080-1300،9000،12000-15000)",
        "through_API": "د OWASP Nettacker API له لارې",
        "API_invalid": "ناباوره API کیلي",
        "unauthorized_IP": "ستاسو IP اجازه نه لري",
        "not_found": "پیدا نشو!",
        "no_subdomain_found": "Subdomain_scan: هیڅ فرعي ډومین تاسیس شوی نه دی!",
        "viewdns_domain_404": "viewdns_reverse_ip_lookup_scan: هیڅ ډومین ونه موندل شو!",
        "browser_session_valid": "ستاسو د برنامه ناسته باوري ده",
        "browser_session_killed": "ستاسو د برنامه ناسته ووژل شوه",
        "updating_database": "ډاټابیس تازه کول ...",
        "database_connect_fail": "ډاټابیس سره ونښلول شو!",
        "inserting_report_db": "ډاټا ډاټابیس ته داخل کړئ",
        "inserting_logs_db": "د ډیټا ډاټابیس ته داخل کړئ",
        "removing_logs_db": "د db څخه زاړه لوګونه لرې کول",
        "len_subdomain_found": "{0} فرعي ماډلونه وموندل شول!",
        "len_domain_found": "{0} ډومینونه وموندل شول!",
        "phpmyadmin_dir_404": "هیڅ د Phpmyadmin dir پیدا نه شو!",
        "DOS_send": "{0} ته د بهرنیو چارو وزارت لیږد لیږل",
        "host_up": "{0} دی! هغه وخت چې بیرته د پښو کولو لپاره اخیستل شوی وي {1}",
        "host_down": "{0} پنگ نه شي کولی!",
        "root_required": "دا اړتیا باید د ریښی په توګه ودرول شي",
        "admin_scan_get": "admin_scan_http_method د ارزښت ارزښت باید GET یا HEAD وي، د GET لپاره ډیزاین ترتیب کړئ.",
        "telnet_connection_timeout": "د ټیلټینټ شبکه {0}: {1} وخت نیسي، غصب کول {2}: {3}",
        "telnet_connection_failed": "د ټیلټینټ اړیکه د {0}: {1} ناکامه شوه، "
        "د بشپړ مرحلې [پروسیجر {2} {3}] لیرې کول! راتلونکی ګام ته لاړ شه",
        "http_auth_success": "http بنسټیز تصدیق بریالیتوب - میزبان: {2}: {3}، کارن: {0}، پاس: {1} وموندل شو!",
        "http_auth_failed": "http بنسټیز تصدیق ناکام شو {0}: {3} د {1}: {2}",
        "http_form_auth_success": "د http فورمه د تصدیق بریالیتوب - میزبان: {2}: {3}، کارن: {0}، پاس: {1} موندلی!",
        "http_form_auth_failed": "د HTTP فارم تصدیق په ناکامۍ سره {0}: {3} د {1}: {2} کاروي",
        "http_ntlm_success": "http ntlm د تصدیق بریالیتوب - میزبان: {2}: {3}، کارن: {0}، پاسور: {1} وموندل شو!",
        "http_ntlm_failed": "http ntlm تایید ناکامۍ {0}: {3} د {1}: {2}",
        "no_response": "د هدف څخه ځواب نشي ترلاسه کولی",
        "category_framework": "وېشنيزه: {0}، چوکاټونه: {1} وموندل شو!",
        "nothing_found": "په {1} کې {1} کې هیڅ شی ندی موندلی!",
        "no_auth": "په {0}: {1} کې هیڅ لیک نه موندل شوی",
    }
