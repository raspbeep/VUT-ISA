Zadani:
Tento projekt se zaměřuje na implementaci nástroje pro tunelování dat prostřednictvím DNS dotazů [1] (použitelným například při DNS data exfiltration útoku [2, 3, 4]).


Klient
Klientská aplikace bude odesílat data souboru/ze STDIN. V případě, že program načítá data ze STDIN je činnost aplikace ukončena přijetím EOF. Program bude možné spustit a ovládat pomocí následujícího předpisu:
dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]

$ dns_sender -u 127.0.0.1 example.com data.txt ./data.txt
$ echo "abc" | dns_sender -u 127.0.0.1 example.com data.txt

Přepínače:
-u slouží k vynucení vzdáleného DNS serveru
pokud není specifikováno, program využije výchozí DNS server nastavený v systému
Poziční parametry:

{BASE_HOST} slouží k nastavení bázové domény všech přenosů
tzn. dotazy budou odesílány na adresy *.{BASE_HOST}, tedy např. edcba.32.1.example.com
{DST_FILEPATH} cesta pod kterou se data uloží na serveru
[SRC_FILEPATH] cesta k souboru který bude odesílán
pokud není specifikováno pak program čte data ze STDIN
Server

Serverová aplikace bude naslouchat na implicitním portu pro DNS komunikaci. Příchozí datové přenosy bude ukládat na disk ve formě souborů. Komunikační protokol mezi klientem a serverem je implementační detail.
dns_receiver {BASE_HOST} {DST_DIRPATH}
$ dns_receiver example.com ./data

Poziční parametry:
{BASE_HOST} slouží k nastavení bázové domény k příjmu dat
{DST_DIRPATH} cesta pod kterou se budou všechny příchozí data/soubory ukládat (cesta specifikovaná klientem bude vytvořena pod tímto adresářem)
