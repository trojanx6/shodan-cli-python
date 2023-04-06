
import requests as req
import json
import folium
from bs4 import BeautifulSoup as btu


class OSİNT():
    def __init__(self):
        self.ipAndDomain = str(input("Domain İp: ")).strip()
        self.APi_KEY = input("=> APİ key Enter:").strip()
        self.headers = {
            "User-Agnet": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
        }
        self.urlmitre = "https://cve.mitre.org/"
        self.PRODUCT = ""
        self.LATITUDE = 0
        self.LONGITUDE = 0
        self.BigJsonDatas()
        self.İP_localtion(self.LATITUDE, self.LONGITUDE)

    def Vulns_cve_found(self, version: str) -> str:
        """
        Girilen version hakkında daha önce ne açığı çıkmış diye bakar
        :parameter version Aix 4.3
        :param version: 1
        :return: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4078]
        :return list
        """
        cve_link_list = []
        item_class_tr = ""
        requests__ = req.get(self.urlmitre + f"cgi-bin/cvekey.cgi?keyword={version.replace(' ', '+')}",
                             headers=self.headers)
        html__ = requests__.text
        soup__ = btu(html__, "html.parser")

        Tablo = soup__.find_all("div", id="TableWithRules")
        for Tbody in Tablo:
            item_class_tr = Tbody.find_all("tr")
        for cve in item_class_tr:
            try:
                nowrap_td = cve.find("td", {"nowrap": "nowrap"}).find("a").get("href")
                cve_link_list.append("https://cve.mitre.org" + nowrap_td)
            except Exception as e:
                ...

        return cve_link_list

    def İP_localtion(self, enlem, boylam):
        """
        Gelen İp adresinin Konumu Harita Üzerinden Gösterir.
        :param enlem:
        :param boylam:
        :return: "index.html" localtion ip
        """
        Map_new = folium.Map(location=[enlem, boylam])
        Map_new.save("index.html")

    def BigJsonDatas(self):
        """
        Girilen İp Adresi Hakkında Bilgiler Toplar


        :parameter ip
        :argument 192.168.1.x
        :returns {"İp":self.ipAndDomain,"Asn":ASN,"Country":COUNTRY_NAME,"Org":ORG,"Host Name":HOSTNAMES,"Domains":domains,"Cpe":CPE,"Os":OS,"Cve":CVE,"Vuln":{"CVS":cvss,"Referans":references,"Summary":summary}}
        """
        urlMain = f"https://api.shodan.io/shodan/host/{self.ipAndDomain}?key={self.APi_KEY}"
        RequestsMain = req.get(urlMain)
        veri = json.loads(RequestsMain.text)
        information = json.dumps(veri, indent=2, sort_keys=True)
        informat = json.loads(information)
        ASN = informat["data"][0]["asn"]
        try:
            CPE = informat["data"][0]["cpe"]
        except:
            CPE = None
        HOSTNAMES = informat["data"][0]["hostnames"]
        COUNTRY_NAME = informat["data"][0]["location"]["country_name"]
        self.LATITUDE = informat["data"][0]["location"]["latitude"]
        self.LONGITUDE = informat["data"][0]["location"]["longitude"]
        ORG = informat["data"][0]["org"]
        OS = informat["data"][0]["os"]

        try:
            self.PRODUCT = informat["data"][0]["product"] + " " + str(informat["data"][0]["version"])
        except:
            self.PRODUCT = ""
        CVE = self.Vulns_cve_found(self.PRODUCT)
        try:
            VULNS = informat["data"][0]["vulns"]
        except:
            VULNS = ""
        try:
            domains = informat["data"][1]["domains"]
        except:
            domains = None
        try:
            for value, item in VULNS.items():
                cvss = item["cvss"]
                references = item["references"]
                summary = item["summary"]
        except:
            cvss = None
            references = None
            summary = None


        dic = {"İp": self.ipAndDomain, "Asn": ASN, "Country": COUNTRY_NAME, "Org": ORG, "Host Name": HOSTNAMES,
                   "Domains": domains, "Cpe": CPE, "Os": OS, "Cve": CVE,
                   "Vuln": {"CVS": cvss, "Referans": references, "Summary": summary}}
        print(dic)





if __name__ == "__main__":
    ps = OSİNT()
