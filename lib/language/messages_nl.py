#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    """
    keep all messages in nl

    Returns:
        all messages in JSON
    """
    return {
        "scan_started": "Nettacker-motor is gestart ...",
        "options": "python nettacker.py [opties]",
        "help_menu": "Toon Nettacker Help Menu",
        "license": "Lees de licentie en overeenkomsten https://github.com/zdresearch/OWASP-Nettacker",
        "engine": "Motor",
        "engine_input": "Motor invoeropties",
        "select_language": "selecteer een taal {0}",
        "range": "scan alle IP's in het bereik",
        "subdomains": "zoek en scan subdomeinen",
        "thread_number_connections": "garennummers voor verbindingen met een host",
        "thread_number_hosts": "garennummers voor scanhosts",
        "save_logs": "sla alle logs in bestand op (results.txt, results.html, results.json)",
        "target": "Doelwit",
        "target_input": "Target invoeropties",
        "target_list": 'doel (en) lijst, gescheiden door ","',
        "read_target": "lees doel (en) uit bestand",
        "scan_method_options": "Opties voor scanmethoden",
        "choose_scan_method": "kies scanmethode {0}",
        "exclude_scan_method": "kies scanmethode om {0} uit te sluiten",
        "username_list": 'gebruikersnaam (s) lijst, gescheiden door ","',
        "username_from_file": "lees gebruikersnaam (s) uit bestand",
        "password_seperator": 'wachtwoord (en) lijst, gescheiden door ","',
        "read_passwords": "lees wachtwoord (s) uit bestand",
        "port_seperator": 'poort (en) lijst, gescheiden door ","',
        "time_to_sleep": "tijd om te slapen tussen elk verzoek",
        "error_target": "Kan het doel (de doelen) niet specificeren",
        "error_target_file": "Kan doel (en) niet specificeren, kan bestand niet openen: {0}",
        "thread_number_warning": "het is beter om een ​​draadnummer lager dan 100 te "
        "gebruiken, trouwens, we gaan door ...",
        "set_timeout": "time-out op {0} seconden instellen, het is te groot, toch? trouwens, we gaan door ...",
        "scan_module_not_found": "deze scanmodule [{0}] niet gevonden!",
        "error_exclude_all": "je kunt niet alle scanmethoden uitsluiten",
        "exclude_module_error": "de {0} module die je hebt geselecteerd om uit te sluiten, is niet gevonden!",
        "method_inputs": "voer methoden invoeren in, bijvoorbeeld: ftp_brute_users = test, admin "
        "& ftp_brute_passwds = read_from_file: /tmp/pass.txt&ftp_brute_port=21",
        "error_reading_file": "kan bestand {0} niet lezen",
        "error_username": "Kan de gebruikersnaam (s) niet specificeren, kan het bestand niet openen: {0}",
        "found": "{0} gevonden! ({1}: {2})",
        "error_password_file": "Kan het wachtwoord of de wachtwoorden niet opgeven, kan het "
        "bestand niet openen: {0}",
        "file_write_error": 'bestand "{0}" is niet beschrijfbaar!',
        "scan_method_select": "kies alstublieft uw scanmethode!",
        "remove_temp": "temp-bestanden verwijderen!",
        "sorting_results": "sorteerresultaten!",
        "done": "gedaan!",
        "start_attack": "begin met het aanvallen van {0}, {1} of {2}",
        "module_not_available": 'deze module "{0}" is niet beschikbaar',
        "error_platform": "helaas kon deze versie van de software gewoon worden uitgevoerd op "
        "linux / osx / windows.",
        "python_version_error": "Je Python-versie wordt niet ondersteund!",
        "skip_duplicate_target": "sla duplicaat doel over (sommige subdomeinen / domeinen kunnen "
        "hetzelfde IP en bereik hebben)",
        "unknown_target": "onbekend type doelwit [{0}]",
        "checking_range": "het bereik {0} controleren ...",
        "checking": "controle van {0} ...",
        "HOST": "HOST",
        "USERNAME": "USERNAME",
        "PASSWORD": "WACHTWOORD",
        "PORT": "HAVEN",
        "TYPE": "TYPE",
        "DESCRIPTION": "BESCHRIJVING",
        "verbose_level": "uitgebreid niveau (0-5) (standaard 0)",
        "software_version": "toon softwareversie",
        "check_updates": "controleer op updates",
        "outgoing_proxy": "uitgaande verbindingen proxy (sokken). voorbeeld socks5: 127.0.0.1:9050, "
        "socks: //127.0.0.1: 9050 socks5: //127.0.0.1: 9050 or socks4: socks4: "
        "//127.0.0.1: 9050, authentication: socks: // gebruikersnaam: wachtwoord @ "
        "127.0.0.1, socks4: // gebruikersnaam: wachtwoord@127.0.0.1, socks5: // "
        "gebruikersnaam: wachtwoord@127.0.0.1",
        "valid_socks_address": "voer een geldig sokkenadres en -poort in. voorbeeld socks5: 127.0.0.1:9050,"
        " socks: //127.0.0.1: 9050, socks5: //127.0.0.1: 9050 or socks4: socks4: "
        "//127.0.0.1: 9050, authentication: socks: // gebruikersnaam: wachtwoord @"
        " 127.0.0.1, socks4: // gebruikersnaam: wachtwoord@127.0.0.1, socks5: // "
        "gebruikersnaam: wachtwoord@127.0.0.1",
        "connection_retries": "Nieuwe pogingen wanneer de time-out van de verbinding is ingesteld (standaard 3)",
        "ftp_connection_timeout": "ftp-verbinding met {0}: {1} time-out, overslaan {2}: {3}",
        "login_successful": "SUCCESVOL INGELOGD!",
        "login_list_error": "SUCCES INGEHEVEN, TOESTEMMING ONTKEND VOOR LIJSTOPDRACHT!",
        "ftp_connection_failed": "ftp-verbinding met {0}: {1} mislukt, hele stap overslaan [proces {2} "
        "van {3}]! naar de volgende stap gaan",
        "input_target_error": "invoerdoel voor de {0} module moet DOMAIN, HTTP of "
        "SINGLE_IPv4 zijn, en {1} overslaan",
        "user_pass_found": "gebruiker: {0} pass: {1} host: {2} poort: {3} gevonden!",
        "file_listing_error": "(GEEN TOESTEMMING VOOR LIJSTBESTANDEN)",
        "trying_message": "proberen {0} van {1} in proces {2} van {3} {4}: {5} ({6})",
        "smtp_connection_timeout": "smtp-verbinding met {0}: {1} time-out, overslaan {2}: {3}",
        "smtp_connection_failed": "smtp-verbinding met {0}: {1} mislukt, hele stap overslaan "
        "[proces {2} van {3}]! naar de volgende stap gaan",
        "ssh_connection_timeout": "ssh-verbinding met {0}: {1} time-out, overslaan {2}: {3}",
        "ssh_connection_failed": "ssh-verbinding met {0}: {1} is mislukt, hele stap overslaan "
        "[proces {2} van {3}]! naar de volgende stap gaan",
        "port/type": "{0} / {1}",
        "port_found": "host: {0} poort: {1} ({2}) gevonden!",
        "target_submitted": "target {0} ingediend!",
        "current_version": "u gebruikt OWASP Nettacker-versie {0} {1} {2} {6} met codenaam {3} {4} {5}",
        "feature_unavailable": 'deze functie is nog niet beschikbaar! voer alstublieft "git clone '
        "https://github.com/zdresearch/OWASP-Nettacker.git or pip install -U "
        "OWASP-Nettacker uit om de laatste versie te krijgen.",
        "available_graph": "maak een grafiek van alle activiteiten en informatie, gebruik HTML-uitvoer. "
        "beschikbare grafieken: {0}",
        "graph_output": "om de grafische functie te gebruiken, moet uw uitvoerbestandsnaam eindigen op "
        '".html" of ".htm"!',
        "build_graph": "grafiek opbouwen ...",
        "finish_build_graph": "bouw grafiek af!",
        "pentest_graphs": "Penetratie Testen grafieken",
        "graph_message": "Deze grafiek is gemaakt door OWASP Nettacker. Grafiek bevat alle modules-activiteiten,"
        " netwerkkaart en gevoelige informatie. Gelieve dit bestand niet met iemand te delen "
        "als het niet betrouwbaar is.",
        "nettacker_report": "OWASP Nettacker-rapport",
        "nettacker_version_details": "Softwaredetails: OWASP Nettacker-versie {0} [{1}] in {2}",
        "no_open_ports": "geen open poorten gevonden!",
        "no_user_passwords": "geen gebruiker / wachtwoord gevonden!",
        "loaded_modules": "{0} modules geladen ...",
        "graph_module_404": "deze grafiekmodule niet gevonden: {0}",
        "graph_module_unavailable": 'deze grafische module "{0}" is niet beschikbaar',
        "ping_before_scan": "ping voordat je de host scant",
        "skipping_target": "het hele doel {0} overslaan en de scanmethode {1} vanwege --ping-before-scan is waar "
        "en het reageerde niet!",
        "not_last_version": "u gebruikt de laatste versie van OWASP Nettacker niet, update alstublieft.",
        "cannot_update": "kan niet controleren op update, controleer uw internetverbinding.",
        "last_version": "U gebruikt de laatste versie van OWASP Nettacker ...",
        "directoy_listing": "directoryvermelding gevonden in {0}",
        "insert_port_message": "voer de poort in via de -g of --methods-args switch in plaats van de URL",
        "http_connection_timeout": "HTTP-verbinding {0} time-out!",
        "wizard_mode": "start wizardmodus",
        "directory_file_404": "geen map of bestand gevonden voor {0} in poort {1}",
        "open_error": "kan {0} niet openen",
        "dir_scan_get": "dir_scan_http_method waarde moet GET of HEAD zijn, zet standaard op GET.",
        "list_methods": "lijst alle methoden args",
        "module_args_error": "kan {0} module-argumenten niet krijgen",
        "trying_process": "proberen {0} van {1} in proces {2} van {3} op {4} ({5})",
        "domain_found": "domein gevonden: {0}",
        "TIME": "TIJD",
        "CATEGORY": "CATEGORIE",
        "module_pattern_404": "kan geen enkele module vinden met het {0} patroon!",
        "enter_default": "vul alstublieft {0} | Standaard [{1}]>",
        "enter_choices_default": "vul alstublieft {0} | keuzes [{1}] | Standaard [{2}]>",
        "all_targets": "de doelen",
        "all_thread_numbers": "het nummer van de draad",
        "out_file": "de bestandsnaam van de uitvoer",
        "all_scan_methods": "de scanmethoden",
        "all_scan_methods_exclude": "de scanmethoden om uit te sluiten",
        "all_usernames": "de gebruikersnamen",
        "all_passwords": "de wachtwoorden",
        "timeout_seconds": "de time-out seconden",
        "all_ports": "de poortnummers",
        "all_verbose_level": "het uitgebreide niveau",
        "all_socks_proxy": "de sokken proxy",
        "retries_number": "het nummer van de pogingen",
        "graph": "een grafiek",
        "subdomain_found": "gevonden subdomein: {0}",
        "select_profile": "selecteer profiel {0}",
        "profile_404": 'het profiel "{0}" niet gevonden!',
        "waiting": "wachten op {0}",
        "vulnerable": "kwetsbaar voor {0}",
        "target_vulnerable": "doel {0}: {1} is kwetsbaar voor {2}!",
        "no_vulnerability_found": "geen kwetsbaarheid gevonden! ({0})",
        "Method": "Methode",
        "API": "API",
        "API_options": "API-opties",
        "start_API": "start de API-service",
        "API_host": "API host-adres",
        "API_port": "API poortnummer",
        "API_debug": "API-foutopsporingsmodus",
        "API_access_key": "API-toegangssleutel",
        "white_list_API": "staat witte lijst hosts toe om verbinding te maken met de API",
        "define_whie_list": "definieer witte lijst hosts, gescheiden met, (voorbeelden: 127.0.0.1, 192.168.0.1/24, "
        "10.0.0.1-10.0.0.255)",
        "gen_API_access_log": "API-toegangslog genereren",
        "API_access_log_file": "API-toegang logboek bestandsnaam",
        "API_port_int": "API-poort moet een geheel getal zijn!",
        "unknown_ip_input": "onbekend ingangstype, geaccepteerde typen zijn SINGLE_IPv4, RANGE_IPv4, CIDR_IPv4",
        "API_key": "* API-sleutel: {0}",
        "ports_int": "poorten moeten gehele getallen zijn! (bijvoorbeeld 80 || 80,1080 || 80,1080-1300,9000,"
        "12000-15000)",
        "through_API": "Via de OWASP Nettacker API",
        "API_invalid": "ongeldige API-sleutel",
        "unauthorized_IP": "uw IP is niet geautoriseerd",
        "not_found": "Niet gevonden!",
        "no_subdomain_found": "subdomain_scan: geen subdomein opgericht!",
        "viewdns_domain_404": "viewdns_reverse_ip_lookup_scan: geen domein gevonden!",
        "browser_session_valid": "uw browsersessie is geldig",
        "browser_session_killed": "je browsersessie vermoord",
        "updating_database": "de database bijwerken ...",
        "database_connect_fail": "Kon niet verbinden met de database!",
        "inserting_report_db": "rapport in de database invoegen",
        "inserting_logs_db": "logs in de database invoegen",
        "removing_logs_db": "het verwijderen van oude logs van db",
        "len_subdomain_found": "{0} subdomein (en) gevonden!",
        "len_domain_found": "{0} domein (en) gevonden!",
        "phpmyadmin_dir_404": "geen phpmyadmin gevonden!",
        "DOS_send": "doS-pakketten verzenden naar {0}",
        "host_up": "{0} is op! De tijd om terug te pingen is {1}",
        "host_down": "Kan {0} niet pingen!",
        "root_required": "dit moet als root worden uitgevoerd",
        "admin_scan_get": "admin_scan_http_method waarde moet GET of HEAD zijn, zet standaard op GET.",
        "telnet_connection_timeout": "telnet-verbinding met {0}: {1} time-out, overslaan {2}: {3}",
        "telnet_connection_failed": "Telnet-verbinding met {0}: {1} is mislukt, hele stap overslaan [proces "
        "{2} van {3}]! naar de volgende stap gaan",
        "http_auth_success": "http basis authenticatiesucces - host: {2}: {3}, gebruiker: {0}, pass: {1} gevonden!",
        "http_auth_failed": "http-basisverificatie mislukt {0}: {3} met behulp van {1}: {2}",
        "http_form_auth_success": "http form authentication success - host: {2}: {3},"
        " user: {0}, pass: {1} gevonden!",
        "http_form_auth_failed": "http form authentication failed to {0}: {3} met behulp van {1}: {2}",
        "http_ntlm_success": "http ntlm authentication success - host: {2}: {3}, user: {0}, pass: {1} gevonden!",
        "http_ntlm_failed": "http ntlm authentication failed to {0}: {3} met behulp van {1}: {2}",
        "no_response": "kan geen reactie krijgen van het doelwit",
        "category_framework": "categorie: {0}, frameworks: {1} gevonden!",
        "nothing_found": "niets gevonden op {0} in {1}!",
        "no_auth": "Geen authenticatie gevonden op {0}: {1}",
    }
