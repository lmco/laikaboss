# Copyright 2015 Lockheed Martin Corporation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
import email
import copy
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.si_module import SI_MODULE
import re
import logging
from IPy import IP

class META_EMAIL(SI_MODULE):
    def __init__(self,):
        self.module_name = "META_EMAIL" 
        # Domain regex
        self.domainMatch = re.compile(r"(([a-z0-9][a-z0-9-]{0,62}\.){0,50}([a-z0-9][a-z0-9-]{0,61}[a-z0-9]\.)((accountants|associates|airforce|allfinanz|amsterdam|abogado|aquarelle|attorney|academy|active|alsace|android|actor|adult|auction|agency|acrot|archi|audio|autos|aero|army|arpa|asia|axa|a[cdefgilmnoqrstuwxz])|(barclaycard|bargains|blackfriday|bnpparibas|budapest|boutique|business|builders|brussels|bloomberg|barclays|bayern|bingo|berlin|black|build|band|bank|beer|best|bike|blue|buzz|boo|bio|bmw|bar|bid|biz|bzh|b[abdefghijmnorstvwyz])|(cancerresearch|cuisinella|camera|capetown|capital|cards|caravan|cartier|careers|career|cash|catering|center|cheap|christmas|citic|claims|cleaning|clinic|clothing|channel|codes|coffee|college|cologne|community|company|computer|condos|construction|consulting|contractors|cooking|country|cricket|credit|creditcard|cruises|church|coach|click|canon|chrome|cymru|chat|casa|cern|city|coop|care|camp|cat|cab|crs|ceo|club|com|cool|coo|cal|c[acdfghiklmnoruvwxyz])|(dance|dating|democrat|delivery|degree|dental|design|dentist|desi|diamonds|doosan|digital|directory|discount|durban|dabur|direct|deals|diet|dclk|docs|dvag|dev|dnp|domains|dad|day|d[ejkmoz])|(education|email|engineering|enterprises|equipment|engineer|eurovision|everbank|emerck|estate|events|exchange|expert|exposed|energy|esq|edu|eat|eus|e[cegrstu])|(feedback|finance|firmdale|financial|fashion|flowers|flsmidth|fishing|forsale|fitness|flights|florist|foundation|frogans|furniture|futbol|fund|fish|fail|farm|fit|foo|frl|fly|f[ijkmor])|(gallery|garden|gifts|gives|glass|globo|graphics|gratis|google|global|gripe|guide|guitars|green|gmail|gbiz|goog|guru|gift|ggee|gent|gle|gmo|gal|gmx|gop|gov|g[abdefghilmnpqrstuwy])|(healthcare|hamburg|holdings|holiday|hangout|hosting|hermes|hiphop|horse|homes|house|haus|help|here|host|hiv|how|h[kmnrtu])|(immobilien|industries|institute|international|investments|irish|insure|immo|info|ifm|ing|iwc|ink|int|ibm|i[delmnoqrst])|(joburg|juegos|jetzt|jobs|jcb|j[emop])|(kaufen|kim|kitchen|koeln|kyoto|kddi|kiwi|kred|krd|k[eghimnprwyz])|(lacaixa|lighting|limited|london|luxury|latrobe|legal|lawyer|lease|loans|lotte|lotto|ltda|luxe|land|limo|lgbt|lidl|life|link|lds|lat|l[abcikrstuvy])|(maison|management|marketing|media|miama|monash|madrid|market|marriott|melbourne|meme|memorial|mortgage|motorcycles|miami|money|mormon|moscow|museum|mango|mini|meet|menu|mobi|moda|moe|mil|mov|m[acdeghklmnopqrstuvwxyz])|(nagoya|neustar|network|ninja|nexus|name|navy|ngo|nhk|nra|nrw|ntt|new|net|nyc|n[acefgilopruz])|(okinawa|organic|osaka|otsuka|ovh|onl|one|ong|ooo|org|om)|(partners|photography|pictures|pharmacy|physio|pizza|place|plumbing|productions|properties|property|photos|party|parts|paris|poker|praxi|press|photo|pohl|prod|prof|porn|pics|pink|post|pub|pro|p[aefghklmnrstwy])|(qa|qpon|quebec)|(republican|restaurant|recipes|reisen|rentals|repair|realtor|report|reviews|ryukyu|rockes|rodeo|rehab|reise|reit|rich|rocks|rsvp|ruhr|rest|rio|rip|red|ren|r[eosuw])|(saarland|schule|services|shiksa|singles|social|solutions|supplies|supply|support|surgery|samsung|schmidt|schwarz|science|shiksha|shriram|software|space|spiegel|style|suzuki|sydney|systems|shoes|solar|sohu|sale|sarl|scot|surf|sexy|soy|sca|scb|sew|sky|s[abcdeghijklmnortuvxyz])|(tattoo|technology|toshiba|tienda|taipei|tatar|temasek|tennis|trust|tires|tirol|today|tokyo|tools|trade|training|travel|town|tips|toys|tui|top|tel|tax|t[cdfghjklmnoprtvwz])|(university|uno|uol|u[agksyz])|(vlaanderen|vacations|versicherung|ventures|voyage|viajes|villas|vision|video|vegas|vodka|vote|voting|voto|vet|v[aceginu])|(williamhill|website|wedding|whoswho|wales|works|watch|webcam|world|wien|wiki|wang|work|wed|wtc|wme|wtf|w[fs])|(xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--45brj9c|xn--55qw42g|xn--55qx5d|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80asehdb|xn--80aswg|xn--90a3ac|xn--c1avg|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czru2d|xn--d1acj3b|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--gecrj9c|xn--h2brj9c|xn--i1b6b1a6a2e|xn--io0a7i|xn--j1amh|xn--j6w193g|xn--kprw13d|xn--kpry57d|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a4f16a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbayh7gpa|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgberp4a5d4ar|xn--mgbx4cd0ab|xn--ngbc5azd|xn--nqv7f|xn--nqv7fs00ema|xn--o3cw4h|xn--ogbpf8fl|xn--p1ai|xn--pgbs0dh|xn--q9jyb4c|xn--rhqv96g|xn--s9brj9c|xn--ses554g|xn--unup4y|xn--wgbh1c|xn--wgbl6a|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xn--1qqw23a|xn--45q11c|xn--4gbrim|xn--b4w605ferd|xn--czr694b|xn--czrs0t|xn--d1alf|xn--flw351e|xn--hxt814e|xn--kput3i|xn--node|xn--p1acf|xn--qcka1pmc|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--xhq521b|xxx|xyz)|(yokohama|yandex|youtube|yachts|yoga|y[et])|(zuerich|zone|zip|z[amw]))$)|(([a-z0-9][a-z0-9-]{0,62}\.){0,50}([a-z0-9][a-z0-9-]{0,61}[a-z0-9]\.)((accountants|associates|airforce|allfinanz|amsterdam|abogado|aquarelle|attorney|academy|active|alsace|android|actor|adult|auction|agency|acrot|archi|audio|autos|aero|army|arpa|asia|axa|a[cdefgilmnoqrstuwxz])|(barclaycard|bargains|blackfriday|bnpparibas|budapest|boutique|business|builders|brussels|bloomberg|barclays|bayern|bingo|berlin|black|build|band|bank|beer|best|bike|blue|buzz|boo|bio|bmw|bar|bid|biz|bzh|b[abdefghijmnorstvwyz])|(cancerresearch|cuisinella|camera|capetown|capital|cards|caravan|cartier|careers|career|cash|catering|center|cheap|christmas|citic|claims|cleaning|clinic|clothing|channel|codes|coffee|college|cologne|community|company|computer|condos|construction|consulting|contractors|cooking|country|cricket|credit|creditcard|cruises|church|coach|click|canon|chrome|cymru|chat|casa|cern|city|coop|care|camp|cat|cab|crs|ceo|club|com|cool|coo|cal|c[acdfghiklmnoruvwxyz])|(dance|dating|democrat|delivery|degree|dental|design|dentist|desi|diamonds|doosan|digital|directory|discount|durban|dabur|direct|deals|diet|dclk|docs|dvag|dev|dnp|domains|dad|day|d[ejkmoz])|(education|email|engineering|enterprises|equipment|engineer|eurovision|everbank|emerck|estate|events|exchange|expert|exposed|energy|esq|edu|eat|eus|e[cegrstu])|(feedback|finance|firmdale|financial|fashion|flowers|flsmidth|fishing|forsale|fitness|flights|florist|foundation|frogans|furniture|futbol|fund|fish|fail|farm|fit|foo|frl|fly|f[ijkmor])|(gallery|garden|gifts|gives|glass|globo|graphics|gratis|google|global|gripe|guide|guitars|green|gmail|gbiz|goog|guru|gift|ggee|gent|gle|gmo|gal|gmx|gop|gov|g[abdefghilmnpqrstuwy])|(healthcare|hamburg|holdings|holiday|hangout|hosting|hermes|hiphop|horse|homes|house|haus|help|here|host|hiv|how|h[kmnrtu])|(immobilien|industries|institute|international|investments|irish|insure|immo|info|ifm|ing|iwc|ink|int|ibm|i[delmnoqrst])|(joburg|juegos|jetzt|jobs|jcb|j[emop])|(kaufen|kim|kitchen|koeln|kyoto|kddi|kiwi|kred|krd|k[eghimnprwyz])|(lacaixa|lighting|limited|london|luxury|latrobe|legal|lawyer|lease|loans|lotte|lotto|ltda|luxe|land|limo|lgbt|lidl|life|link|lds|lat|l[abcikrstuvy])|(maison|management|marketing|media|miama|monash|madrid|market|marriott|melbourne|meme|memorial|mortgage|motorcycles|miami|money|mormon|moscow|museum|mango|mini|meet|menu|mobi|moda|moe|mil|mov|m[acdeghklmnopqrstuvwxyz])|(nagoya|neustar|network|ninja|nexus|name|navy|ngo|nhk|nra|nrw|ntt|new|net|nyc|n[acefgilopruz])|(okinawa|organic|osaka|otsuka|ovh|onl|one|ong|ooo|org|om)|(partners|photography|pictures|pharmacy|physio|pizza|place|plumbing|productions|properties|property|photos|party|parts|paris|poker|praxi|press|photo|pohl|prod|prof|porn|pics|pink|post|pub|pro|p[aefghklmnrstwy])|(qa|qpon|quebec)|(republican|restaurant|recipes|reisen|rentals|repair|realtor|report|reviews|ryukyu|rockes|rodeo|rehab|reise|reit|rich|rocks|rsvp|ruhr|rest|rio|rip|red|ren|r[eosuw])|(saarland|schule|services|shiksa|singles|social|solutions|supplies|supply|support|surgery|samsung|schmidt|schwarz|science|shiksha|shriram|software|space|spiegel|style|suzuki|sydney|systems|shoes|solar|sohu|sale|sarl|scot|surf|sexy|soy|sca|scb|sew|sky|s[abcdeghijklmnortuvxyz])|(tattoo|technology|toshiba|tienda|taipei|tatar|temasek|tennis|trust|tires|tirol|today|tokyo|tools|trade|training|travel|town|tips|toys|tui|top|tel|tax|t[cdfghjklmnoprtvwz])|(university|uno|uol|u[agksyz])|(vlaanderen|vacations|versicherung|ventures|voyage|viajes|villas|vision|video|vegas|vodka|vote|voting|voto|vet|v[aceginu])|(williamhill|website|wedding|whoswho|wales|works|watch|webcam|world|wien|wiki|wang|work|wed|wtc|wme|wtf|w[fs])|(xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--45brj9c|xn--55qw42g|xn--55qx5d|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80asehdb|xn--80aswg|xn--90a3ac|xn--c1avg|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czru2d|xn--d1acj3b|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--gecrj9c|xn--h2brj9c|xn--i1b6b1a6a2e|xn--io0a7i|xn--j1amh|xn--j6w193g|xn--kprw13d|xn--kpry57d|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a4f16a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbayh7gpa|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgberp4a5d4ar|xn--mgbx4cd0ab|xn--ngbc5azd|xn--nqv7f|xn--nqv7fs00ema|xn--o3cw4h|xn--ogbpf8fl|xn--p1ai|xn--pgbs0dh|xn--q9jyb4c|xn--rhqv96g|xn--s9brj9c|xn--ses554g|xn--unup4y|xn--wgbh1c|xn--wgbl6a|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xn--1qqw23a|xn--45q11c|xn--4gbrim|xn--b4w605ferd|xn--czr694b|xn--czrs0t|xn--d1alf|xn--flw351e|xn--hxt814e|xn--kput3i|xn--node|xn--p1acf|xn--qcka1pmc|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--xhq521b|xxx|xyz)|(yokohama|yandex|youtube|yachts|yoga|y[et])|(zuerich|zone|zip|z[amw]))(?=[^a-z0-9]))")
        # Email Address
        self.emailMatch = re.compile(r"([a-z0-9!#$%\\&*+/?^_`{|}~-][\.a-z0-9!#$%&'*+/?^_`{|}~-]{0,200}@((([a-z0-9][a-z0-9-]{0,62}\.){0,50}([a-z0-9][a-z0-9-]{0,61}[a-z0-9]\.)((accountants|associates|airforce|allfinanz|amsterdam|abogado|aquarelle|attorney|academy|active|alsace|android|actor|adult|auction|agency|acrot|archi|audio|autos|aero|army|arpa|asia|axa|a[cdefgilmnoqrstuwxz])|(barclaycard|bargains|blackfriday|bnpparibas|budapest|boutique|business|builders|brussels|bloomberg|barclays|bayern|bingo|berlin|black|build|band|bank|beer|best|bike|blue|buzz|boo|bio|bmw|bar|bid|biz|bzh|b[abdefghijmnorstvwyz])|(cancerresearch|cuisinella|camera|capetown|capital|cards|caravan|cartier|careers|career|cash|catering|center|cheap|christmas|citic|claims|cleaning|clinic|clothing|channel|codes|coffee|college|cologne|community|company|computer|condos|construction|consulting|contractors|cooking|country|cricket|credit|creditcard|cruises|church|coach|click|canon|chrome|cymru|chat|casa|cern|city|coop|care|camp|cat|cab|crs|ceo|club|com|cool|coo|cal|c[acdfghiklmnoruvwxyz])|(dance|dating|democrat|delivery|degree|dental|design|dentist|desi|diamonds|doosan|digital|directory|discount|durban|dabur|direct|deals|diet|dclk|docs|dvag|dev|dnp|domains|dad|day|d[ejkmoz])|(education|email|engineering|enterprises|equipment|engineer|eurovision|everbank|emerck|estate|events|exchange|expert|exposed|energy|esq|edu|eat|eus|e[cegrstu])|(feedback|finance|firmdale|financial|fashion|flowers|flsmidth|fishing|forsale|fitness|flights|florist|foundation|frogans|furniture|futbol|fund|fish|fail|farm|fit|foo|frl|fly|f[ijkmor])|(gallery|garden|gifts|gives|glass|globo|graphics|gratis|google|global|gripe|guide|guitars|green|gmail|gbiz|goog|guru|gift|ggee|gent|gle|gmo|gal|gmx|gop|gov|g[abdefghilmnpqrstuwy])|(healthcare|hamburg|holdings|holiday|hangout|hosting|hermes|hiphop|horse|homes|house|haus|help|here|host|hiv|how|h[kmnrtu])|(immobilien|industries|institute|international|investments|irish|insure|immo|info|ifm|ing|iwc|ink|int|ibm|i[delmnoqrst])|(joburg|juegos|jetzt|jobs|jcb|j[emop])|(kaufen|kim|kitchen|koeln|kyoto|kddi|kiwi|kred|krd|k[eghimnprwyz])|(lacaixa|lighting|limited|london|luxury|latrobe|legal|lawyer|lease|loans|lotte|lotto|ltda|luxe|land|limo|lgbt|lidl|life|link|lds|lat|l[abcikrstuvy])|(maison|management|marketing|media|miama|monash|madrid|market|marriott|melbourne|meme|memorial|mortgage|motorcycles|miami|money|mormon|moscow|museum|mango|mini|meet|menu|mobi|moda|moe|mil|mov|m[acdeghklmnopqrstuvwxyz])|(nagoya|neustar|network|ninja|nexus|name|navy|ngo|nhk|nra|nrw|ntt|new|net|nyc|n[acefgilopruz])|(okinawa|organic|osaka|otsuka|ovh|onl|one|ong|ooo|org|om)|(partners|photography|pictures|pharmacy|physio|pizza|place|plumbing|productions|properties|property|photos|party|parts|paris|poker|praxi|press|photo|pohl|prod|prof|porn|pics|pink|post|pub|pro|p[aefghklmnrstwy])|(qa|qpon|quebec)|(republican|restaurant|recipes|reisen|rentals|repair|realtor|report|reviews|ryukyu|rockes|rodeo|rehab|reise|reit|rich|rocks|rsvp|ruhr|rest|rio|rip|red|ren|r[eosuw])|(saarland|schule|services|shiksa|singles|social|solutions|supplies|supply|support|surgery|samsung|schmidt|schwarz|science|shiksha|shriram|software|space|spiegel|style|suzuki|sydney|systems|shoes|solar|sohu|sale|sarl|scot|surf|sexy|soy|sca|scb|sew|sky|s[abcdeghijklmnortuvxyz])|(tattoo|technology|toshiba|tienda|taipei|tatar|temasek|tennis|trust|tires|tirol|today|tokyo|tools|trade|training|travel|town|tips|toys|tui|top|tel|tax|t[cdfghjklmnoprtvwz])|(university|uno|uol|u[agksyz])|(vlaanderen|vacations|versicherung|ventures|voyage|viajes|villas|vision|video|vegas|vodka|vote|voting|voto|vet|v[aceginu])|(williamhill|website|wedding|whoswho|wales|works|watch|webcam|world|wien|wiki|wang|work|wed|wtc|wme|wtf|w[fs])|(xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--45brj9c|xn--55qw42g|xn--55qx5d|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80asehdb|xn--80aswg|xn--90a3ac|xn--c1avg|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czru2d|xn--d1acj3b|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--gecrj9c|xn--h2brj9c|xn--i1b6b1a6a2e|xn--io0a7i|xn--j1amh|xn--j6w193g|xn--kprw13d|xn--kpry57d|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a4f16a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbayh7gpa|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgberp4a5d4ar|xn--mgbx4cd0ab|xn--ngbc5azd|xn--nqv7f|xn--nqv7fs00ema|xn--o3cw4h|xn--ogbpf8fl|xn--p1ai|xn--pgbs0dh|xn--q9jyb4c|xn--rhqv96g|xn--s9brj9c|xn--ses554g|xn--unup4y|xn--wgbh1c|xn--wgbl6a|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xn--1qqw23a|xn--45q11c|xn--4gbrim|xn--b4w605ferd|xn--czr694b|xn--czrs0t|xn--d1alf|xn--flw351e|xn--hxt814e|xn--kput3i|xn--node|xn--p1acf|xn--qcka1pmc|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--xhq521b|xxx|xyz)|(yokohama|yandex|youtube|yachts|yoga|y[et])|(zuerich|zone|zip|z[amw]))$)|(([a-z0-9][a-z0-9-]{0,62}\.){0,50}([a-z0-9][a-z0-9-]{0,61}[a-z0-9]\.)((accountants|associates|airforce|allfinanz|amsterdam|abogado|aquarelle|attorney|academy|active|alsace|android|actor|adult|auction|agency|acrot|archi|audio|autos|aero|army|arpa|asia|axa|a[cdefgilmnoqrstuwxz])|(barclaycard|bargains|blackfriday|bnpparibas|budapest|boutique|business|builders|brussels|bloomberg|barclays|bayern|bingo|berlin|black|build|band|bank|beer|best|bike|blue|buzz|boo|bio|bmw|bar|bid|biz|bzh|b[abdefghijmnorstvwyz])|(cancerresearch|cuisinella|camera|capetown|capital|cards|caravan|cartier|careers|career|cash|catering|center|cheap|christmas|citic|claims|cleaning|clinic|clothing|channel|codes|coffee|college|cologne|community|company|computer|condos|construction|consulting|contractors|cooking|country|cricket|credit|creditcard|cruises|church|coach|click|canon|chrome|cymru|chat|casa|cern|city|coop|care|camp|cat|cab|crs|ceo|club|com|cool|coo|cal|c[acdfghiklmnoruvwxyz])|(dance|dating|democrat|delivery|degree|dental|design|dentist|desi|diamonds|doosan|digital|directory|discount|durban|dabur|direct|deals|diet|dclk|docs|dvag|dev|dnp|domains|dad|day|d[ejkmoz])|(education|email|engineering|enterprises|equipment|engineer|eurovision|everbank|emerck|estate|events|exchange|expert|exposed|energy|esq|edu|eat|eus|e[cegrstu])|(feedback|finance|firmdale|financial|fashion|flowers|flsmidth|fishing|forsale|fitness|flights|florist|foundation|frogans|furniture|futbol|fund|fish|fail|farm|fit|foo|frl|fly|f[ijkmor])|(gallery|garden|gifts|gives|glass|globo|graphics|gratis|google|global|gripe|guide|guitars|green|gmail|gbiz|goog|guru|gift|ggee|gent|gle|gmo|gal|gmx|gop|gov|g[abdefghilmnpqrstuwy])|(healthcare|hamburg|holdings|holiday|hangout|hosting|hermes|hiphop|horse|homes|house|haus|help|here|host|hiv|how|h[kmnrtu])|(immobilien|industries|institute|international|investments|irish|insure|immo|info|ifm|ing|iwc|ink|int|ibm|i[delmnoqrst])|(joburg|juegos|jetzt|jobs|jcb|j[emop])|(kaufen|kim|kitchen|koeln|kyoto|kddi|kiwi|kred|krd|k[eghimnprwyz])|(lacaixa|lighting|limited|london|luxury|latrobe|legal|lawyer|lease|loans|lotte|lotto|ltda|luxe|land|limo|lgbt|lidl|life|link|lds|lat|l[abcikrstuvy])|(maison|management|marketing|media|miama|monash|madrid|market|marriott|melbourne|meme|memorial|mortgage|motorcycles|miami|money|mormon|moscow|museum|mango|mini|meet|menu|mobi|moda|moe|mil|mov|m[acdeghklmnopqrstuvwxyz])|(nagoya|neustar|network|ninja|nexus|name|navy|ngo|nhk|nra|nrw|ntt|new|net|nyc|n[acefgilopruz])|(okinawa|organic|osaka|otsuka|ovh|onl|one|ong|ooo|org|om)|(partners|photography|pictures|pharmacy|physio|pizza|place|plumbing|productions|properties|property|photos|party|parts|paris|poker|praxi|press|photo|pohl|prod|prof|porn|pics|pink|post|pub|pro|p[aefghklmnrstwy])|(qa|qpon|quebec)|(republican|restaurant|recipes|reisen|rentals|repair|realtor|report|reviews|ryukyu|rockes|rodeo|rehab|reise|reit|rich|rocks|rsvp|ruhr|rest|rio|rip|red|ren|r[eosuw])|(saarland|schule|services|shiksa|singles|social|solutions|supplies|supply|support|surgery|samsung|schmidt|schwarz|science|shiksha|shriram|software|space|spiegel|style|suzuki|sydney|systems|shoes|solar|sohu|sale|sarl|scot|surf|sexy|soy|sca|scb|sew|sky|s[abcdeghijklmnortuvxyz])|(tattoo|technology|toshiba|tienda|taipei|tatar|temasek|tennis|trust|tires|tirol|today|tokyo|tools|trade|training|travel|town|tips|toys|tui|top|tel|tax|t[cdfghjklmnoprtvwz])|(university|uno|uol|u[agksyz])|(vlaanderen|vacations|versicherung|ventures|voyage|viajes|villas|vision|video|vegas|vodka|vote|voting|voto|vet|v[aceginu])|(williamhill|website|wedding|whoswho|wales|works|watch|webcam|world|wien|wiki|wang|work|wed|wtc|wme|wtf|w[fs])|(xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--45brj9c|xn--55qw42g|xn--55qx5d|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80asehdb|xn--80aswg|xn--90a3ac|xn--c1avg|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czru2d|xn--d1acj3b|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--gecrj9c|xn--h2brj9c|xn--i1b6b1a6a2e|xn--io0a7i|xn--j1amh|xn--j6w193g|xn--kprw13d|xn--kpry57d|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a4f16a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbayh7gpa|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgberp4a5d4ar|xn--mgbx4cd0ab|xn--ngbc5azd|xn--nqv7f|xn--nqv7fs00ema|xn--o3cw4h|xn--ogbpf8fl|xn--p1ai|xn--pgbs0dh|xn--q9jyb4c|xn--rhqv96g|xn--s9brj9c|xn--ses554g|xn--unup4y|xn--wgbh1c|xn--wgbl6a|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xn--1qqw23a|xn--45q11c|xn--4gbrim|xn--b4w605ferd|xn--czr694b|xn--czrs0t|xn--d1alf|xn--flw351e|xn--hxt814e|xn--kput3i|xn--node|xn--p1acf|xn--qcka1pmc|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--xhq521b|xxx|xyz)|(yokohama|yandex|youtube|yachts|yoga|y[et])|(zuerich|zone|zip|z[amw]))(?=[^\w]))))")
        # IPv4 Address
        self.ipMatch = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        # IPv6 Address
        self.ipv6Match = re.compile(r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))')

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        e = email.message_from_string(scanObject.buffer)
        
        sIParray = []
        domainArray = []
        toArray  = []
        frArray  = []
        rtoArray  = []
        rfrArray  = []
        metaDict = {}
        metaDictDecode = {}
        message_id_domain = ""

        for key, value in e.items():
            try:
                key = key.encode('ascii', 'ignore')
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                key = "UNPARSEABLE KEY"
            try:
                value = value.encode('ascii', 'ignore')
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                value = "UNPARSEABLE VALUE"

            #key = key.replace(".", "[d]") # Removing as this will be handled in the framework
            
            metaDict = self._addToMetaDict(metaDict, key, value)
            
            if key.lower() == "dkim-signature":
                detailArray = value.lower().split()
                for detail in detailArray: #add one at a time due to current implementation
                    metaDict = self._addToMetaDict(metaDict, "dkim-signature-search", detail)
                    
            if key.lower() == "to" or key.lower() == "cc" or key.lower() == "bcc" or key.lower() == "x-cirt-orcpt":
                lst_emails = self.emailMatch.findall(value.lower())
                for singleEmail in lst_emails:
                    if singleEmail not in toArray:
                        toArray.append(singleEmail)
                        rtoArray.append(singleEmail[::-1]) # reversed
            if key.lower() == "from" or key.lower() == "x-cirt-from":
                lst_emails = self.emailMatch.findall(value.lower())
                for singleEmail in lst_emails:
                    if singleEmail not in frArray:
                        frArray.append(singleEmail)
                        rfrArray.append(singleEmail[::-1])
            
            if key.lower() == 'message-id':
                if '@' in value:
                    message_id_domain = value.split('@')[1].strip('>')
                    

            #for every value, try finding IPs and domains
            #escape single quotes
            strIPs = value.replace("'", "\\'").lower()
            IPs = self.ipMatch.findall(strIPs )
            IPv6s =  self.ipv6Match.findall(strIPs)
            domains = self.domainMatch.findall(strIPs)
            
            
            for IPv4 in IPs:
                if not IPv4 in sIParray:
                    IPyIP= IP(IPv4)
                    sIParray.append(str(IPyIP))
                    #convert the IP to an integer
            for IPv6 in IPv6s:
                strIPv6 = ""
                if type(IPv6) == tuple:
                    strIPv6 = IPv6[0]
                elif type(IPv6) == str:
                    strIPv6 = IPv6
                if not strIPv6 in sIParray:
                    IPyIP= IP(strIPv6)
                    sIParray.append(str(strIPv6))
                    #convert the IP to an integer
            for domain in domains:
                strDomain = ""
                if type(domain) == tuple:
                    strDomain = domain[0]
                elif type(domain) == str:
                    strDomain = domain
                if not strDomain in domainArray:
                    domainArray.append(str(strDomain))
 
        # Copy the headers and run them through decode to pull out the printable ASCII version
        metaDictDecode = copy.deepcopy(metaDict)
        for key, value in metaDictDecode.iteritems():
            try:
                decoded, format = email.Header.decode_header(value)[0]
                # if the encoding it something other than utf-8, attempt to convert it
                if format and format != 'utf-8':
                    metaDictDecode[key] = unicode(decoded, format).encode('utf-8')
                # format is either empty (assumes ASCII) or utf-8 (our preferred encoding)
                else:
                    metaDictDecode[key] = decoded
                    
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except: 
                metaDictDecode[key] = ""

        # Add Message-ID to scan object as uniqID
        if not scanObject.uniqID:
            if "message-id" in metaDict:
                scanObject.uniqID = metaDict['message-id']

        if message_id_domain:
            scanObject.addMetadata(self.module_name, "MessageID_Domain", message_id_domain)

        scanObject.addMetadata(self.module_name, "String_IPs", sIParray)
        scanObject.addMetadata(self.module_name, "Domains", domainArray, unique=True)
        scanObject.addMetadata(self.module_name, "Recipients", toArray)
        scanObject.addMetadata(self.module_name, "Senders", frArray)
        scanObject.addMetadata(self.module_name, "Recipients_reverse", rtoArray)
        scanObject.addMetadata(self.module_name, "Senders_reverse", rfrArray)
        scanObject.addMetadata(self.module_name, "Headers", metaDict)
        scanObject.addMetadata(self.module_name, "Headers-Decode", metaDictDecode)
            
        return moduleResult
    
    @staticmethod
    def _addToMetaDict(metaDict, key, value):
        thisKey = key
        thisValue = value
        if thisKey.lower() in metaDict:
            newHeader = []
            if type(metaDict[str(thisKey.lower())]) is list:
                newHeader.extend(metaDict[str(thisKey.lower())])
            else:
                newHeader.append(metaDict[str(thisKey.lower())])
            try:
                newHeader.append(str(thisValue))
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                logging.debug("Cannot convert email header key/value pair")
            del metaDict[str(thisKey.lower())]
            metaDict[str(thisKey.lower())] = newHeader
        else:
            try:
                metaDict[str(thisKey.lower())] = thisValue
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                logging.debug("Cannot convert email header key/value pair")
                
        return metaDict
