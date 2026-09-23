#!/usr/bin/env python3
"""
Phase 1b — Seed targets from curated e-commerce domain list.

Supplements umbrella-based discovery with a hand-curated list of known DTC
and e-commerce brands.  Each domain is fingerprinted live to confirm it is
currently running Shopify or WordPress/WooCommerce; only confirmed hits are
written to targets.csv.

Appends to data/targets.csv (does not duplicate existing entries).
Rank is set to 0 for seeded entries so they sort after Umbrella results.
"""
import asyncio
import csv
import sys
from pathlib import Path

import httpx

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
OUT_CSV  = DATA_DIR / "targets.csv"

WORKERS = 60
TIMEOUT = 6.0
UA      = "SiteGuard-Research/1.0 (+https://siteguard-trust.lovable.app/methodology)"

# ── Curated candidate domains ─────────────────────────────────────────────────
# Mix of high-confidence Shopify DTC brands and likely WooCommerce stores.
# Fingerprinting confirms actual platform at scan time.

SEED_DOMAINS = [
    # ── Shopify Plus / confirmed DTC brands ─────────────────────────────────
    "allbirds.com", "gymshark.com", "mvmt.com", "bombas.com",
    "ridge.com", "casetify.com", "ruggable.com", "mejuri.com",
    "represent.com", "brumate.com", "puravidabracelets.com",
    "tentree.com", "bellroy.com", "outerknown.com", "quayaustralia.com",
    "colourpop.com", "harney.com", "ohpolly.com", "nastygal.com",
    "cuts.com", "nobull.com", "shinesty.com", "kotn.com",
    "frankandoak.com", "lunya.co", "summersalt.com", "untuckit.com",
    "gfuel.com", "tecovas.com", "frankbody.com", "away.com",
    "glossier.com", "beardbrand.com", "jungalow.com", "manduka.com",
    "mackweldon.com", "chubbiesshorts.com", "rothys.com",
    "ugmonk.com", "deathwishcoffee.com", "blendjet.com", "ooni.com",
    "gorjana.com", "rarebeauty.com", "alphalete.com", "gymreapers.com",
    "fahertybrand.com", "vuoriclothing.com", "marinelayer.com",
    "motelrocks.com", "peppermayo.com", "ganni.com",
    "dagne-dover.com", "parachutehome.com", "brooklinen.com",
    "buffy.co", "cultiver.com", "magicspoon.com", "drinkmudwtr.com",
    "nomadgoods.com", "grovemade.com", "ana-luisa.com",
    "catbirnyc.com", "vrai.com", "nordgreen.com", "vincero.com",
    "sunski.com", "knockaround.com", "voluspa.com", "paddywax.com",
    "erin-condren.com", "artifact-uprising.com", "peakdesign.com",
    "knickey.com", "birdiesshoes.com", "tasc-performance.com",
    "grayers.com", "richer-poorer.com", "motelrocks.com",
    "supergoop.com", "tatcha.com", "versed.com", "saie.com",
    "haus-labs.com", "ilia.com", "inkey-list.com",
    "hexclad.com", "madeincookware.com", "caraway.com", "ourplace.com",
    "greatjones.co", "fieldcompany.com", "smithey.com",
    "fringe-sport.com", "titan-fitness.com", "repfitness.com",
    "cotopaxi.com", "snowe.com", "etcetc.com",
    "darnedtough.com", "vivobarefoot.com", "xerofoot.com",
    "blundstone.com", "sorel.com", "thursday.com",
    "beckett-simonon.com", "kizik.com",
    "fellow.com", "baratza.com",
    "christopherward.com", "filippoloreti.com",
    "herschel.com", "state-bags.com", "baggus.com",
    "aersf.com", "tombihn.com", "chrome-industries.com",
    "keap.com", "prosperitycandle.com",
    "chatbooks.com", "mpix.com",
    "mbody.co", "popflexactive.com",
    "loq.com", "staud.clothing", "meshki.com",
    "ritual.com", "care-of.com", "athleticgreens.com",
    "transparentlabs.com",
    "sollybabyco.com", "lovevery.com", "nuggetcomfort.com",
    "wildearth.com", "farmersdog.com", "nomnomnow.com",
    "ollie.com",
    "shopbando.com",
    "tigermist.com",
    "poppyandbark.com", "maguire.ca",
    "serengetee.com", "tentree.com",
    "wanderlust-and-co.com",
    "studio-neat.com",
    "waterfielddesigns.com",
    "gocube.com", "oakywood.shop",
    "hardgraft.com",
    "momentlens.co",
    "bulletproof.com", "fourthandheart.com", "primalpalate.com",
    "thespicehouse.com",
    "intelligentsiacoffee.com", "vervecoffee.com",
    "dropelixir.com",
    # ── Likely WordPress / WooCommerce ──────────────────────────────────────
    "sweetmarias.com",
    "prima-coffee.com",
    "seattlecoffeegear.com",
    "orphanespresso.com",
    "baratza.com",
    "clivecc.com",
    "mountainroseherbs.com",
    "amerisleep.com",
    "ghostbed.com",
    "plushbeds.com",
    "novosbed.com",
    "winkbeds.com",
    "nest-bedding.com",
    "mygreenmattress.com",
    "bedinabox.com",
    "sleep-ez.com",
    "foamfactory.com",
    "spindlemattress.com",
    "avocadogreenmattress.com",
    "thermoworks.com",
    "fieldcompany.com",
    "realmilkpaint.com",
    "generalfinishes.com",
    "guitarfetish.com",
    "stewmac.com",
    "allparts.com",
    "graphtech.com",
    "sperzel.com",
    "bigbends.com",
    "manchesterguitarcraft.com",
    "igourmet.com",
    "murrayscheese.com",
    "zingermans.com",
    "heritagefoods.com",
    "vitalchoice.com",
    "getmainelobster.com",
    "localharvest.org",
    "tackledirect.com",
    "lancasterarchery.com",
    "3riversarchery.com",
    "prostockhockey.com",
    "true-team.com",
    "countycomm.com",
    "lifestraw.com",
    "survivalstraps.com",
    "cotswoldoutdoor.com",
    "altitude-sports.com",
    "purism.com",
    "system76.com",
    "elementaryos.org",
    "yoast.com",
    "pluginrepublic.com",
    "iconicwp.com",
    "toolset.com",
    "ninjaforms.com",
    "wpforms.com",
    "coolstuffinc.com",
    "miniaturemarket.com",
    "channelfireball.com",
    "nalgene.com",
    "klean-kanteen.com",
    "bigagnes.com",
    "leki.com",
    "worldsoccershop.com",
    "soccer-pro.com",
    "mister-art.com",
    "createforless.com",
    "arteza.com",
    # ── Additional e-commerce candidates (platform unknown — fingerprinter decides) ─
    "caseify.com",
    "roguefitness.com",
    "elitefts.com",
    "fringe-sport.com",
    "archonfitness.com",
    "archon-fitness.com",
    "repfitness.com",
    "foamnfabulous.com",
    "tigerlilyclothing.com",
    "showpo.com",
    "witchery.com.au",
    "thereformation.com",
    "prAna.com",
    "fjallraven.us",
    "outdoorresearch.com",
    "patagonia.com",
    "dpx-gear.com",
    "barebones.com",
    "portablekitchen.com",
    "dexshell.com",
    "kammok.com",
    "coalatree.com",
    "paktlv.com",
    "tropicfeel.com",
    "minaal.com",
    "tortugabackpacks.com",
    "goruck.com",
    "maxpedition.com",
    "helikon-tex.com",
    "snugpak.com",
    "rab.equipment",
    "hillsound.com",
    "icespikes.com",
    "julbo.com",
    "osprey.com",
    "deuter.com",
    "gregory-pac.com",
    "lowe-alpine.com",
    "haglofs.com",
    "vaude.com",
    "mammut.com",
    "millet-mountain.com",
    "scarpa-us.com",
    "lacoste.com",
    "saucony.com",
    "newbalance.com",
    "asics.com",
    "hoka.com",
    "on-running.com",
    "brookssports.com",
    "salomonrunning.com",
    "altrashoesusa.com",
    "altra-running.com",
    "inov-8.com",
    "icebug.com",
    "skechersusa.com",
    "sketchers.com",
    "fitflop.com",
    "sanuk.com",
    "keen.com",
    "merrellshoes.com",
    "columbiaomni.com",
    "columbia.com",
    "northface.com",
    "ralphlauren.com",
    "calvinklein.com",
    "tommyhilfiger.com",
    "michaelkors.com",
    "coach.com",
    "katespade.com",
    "tory-burch.com",
    "stellamccartney.com",
    "shopspring.com",
    "shopstyle.com",
    "revolve.com",
    "asos.com",
    "missguided.com",
    "prettylittlething.com",
    "boohoo.com",
    "hm.com",
    "weekday.com",
    "monki.com",
    "arket.com",
    "cos-stores.com",
    "otherstories.com",
    "acnestudios.com",
    "toteme-studio.com",
    "nanshy.co.uk",
    "reiss.com",
    "allsaints.com",
    "whistlesclothing.com",
    "jigsaw-online.com",
    "hobbs.co.uk",
    "joebrowns.co.uk",
    "fatface.com",
    "boden.co.uk",
    "white-stuff.com",
    "seasalt-cornwall.co.uk",
    "notonthehighstreet.com",
    "etsy.com",
    "not-ordinary.co.uk",
    "folksy.com",
    "uncommongoods.com",
    "uncommon-goods.com",
    "firebox.com",
    "firebox.co.uk",
    "hawkersco.com",
    "warby-parker.com",
    "eyebuydirect.com",
    "firmoo.com",
    "zenni.com",
    "lensabl.com",
    "clearly.ca",
    "specsavers.com",
    "visionexpress.com",
    "boots.com",
    "superdrug.com",
    "lookfantastic.com",
    "feelunique.com",
    "beautybay.com",
    "cultbeauty.co.uk",
    "spacenk.com",
    "libertylondon.com",
    "harrods.com",
    "selfridges.com",
    "net-a-porter.com",
    "matches-fashion.com",
    "farfetch.com",
    "yoox.com",
    "mytheresa.com",
    "ssense.com",
    "endclothing.com",
    "mr-porter.com",
    "oki-ni.com",
    "coggles.com",
    "brownsfashion.com",
    "harveynichols.com",
    "flannels.com",
    "house-of-fraser.com",
    "johnlewis.com",
    "marksandspencer.com",
    "debenhams.com",
    "newlook.com",
    "next.co.uk",
    "tu.co.uk",
    "georgeadnotawebsite.com",
    "peacocks.co.uk",
    "primark.com",
    "asda-george.com",
    "tesco-clothing.com",
    "sainsburys-clothing.co.uk",
    "very.co.uk",
    "littlewoods.com",
    "studio.co.uk",
    "sportsdirect.com",
    "jdsports.co.uk",
    "footasylum.com",
    "size.co.uk",
    "schuh.co.uk",
    "office.co.uk",
    "dune-london.com",
    "aldoshoes.com",
    "stevemadden.com",
    "samanthaonline.com",
    "wildflowershoes.com",
    "alexanderwang.com",
    "jimmychoo.com",
    "manoloblahnik.com",
    "louboutinworld.com",
    "gucci.com",
    "prada.com",
    "louisvuitton.com",
    "chanel.com",
    "dior.com",
    "hermes.com",
    "burberry.com",
    "mulberry.com",
    "aspinal.com",
    "smythson.com",
    "globe-trotter.com",
    "rimowa.com",
    "samsonite.com",
    "tumi.com",
    "briggs-riley.com",
    "biaggi.com",
    "arlo-skye.com",
    "july.com",
    "monos.com",
    "horizn-studios.com",
    "delsey.com",
    "eastpak.com",
    "kipling.com",
    "jansport.com",
    "fjallraven.com",
    "pacsafe.com",
    "travelon.com",
    "eagle-creek.com",
    "highsierra.com",
    "dakine.com",
    "burton.com",
    "rome-sds.com",
    "nitrosnowboards.com",
    "gnu-snowboards.com",
    "libtech.com",
    "mervin.com",
    "rossignol.com",
    "atomicski.com",
    "headski.com",
    "dynastar.com",
    "blizzard-tecnica.com",
    "volkl.com",
    "fischer-ski.com",
    "nordica.com",
    "dalbello.com",
    "langeskis.com",
    "k2snow.com",
    "whitedotskis.com",
    "moment-skis.com",
    "icelantic-skis.com",
    "oyshoregear.com",
    "magicmountainracing.com",
    "bsrbikeshop.com",
    "jenson-usa.com",
    "competitive-cyclist.com",
    "performance-bicycle.com",
    "nashbar.com",
    "probikekit.com",
    "wiggle.com",
    "chainreactioncycles.com",
    "chainreaction.com",
    "cyclingdeal.com.au",
    "99bikes.com.au",
    "bicistore.es",
    "decathlon.co.uk",
    "decathlon.com",
    "intersport.com",
    "sport2000.com",
    "sportscheck.com",
    "running4.co.uk",
    "runnersneed.com",
    "sweatshop.co.uk",
    "athletefoot.com",
    "fleetfeet.com",
    "lukespeed.com",
    "roadrunnersports.com",
    "racerready.com",
    "triathlete-sports.com",
    "wetsuitoutlet.co.uk",
    "saltrock.com",
    "o-neill.com",
    "billabong.com",
    "quiksilver.com",
    "roxy.com",
    "volcom.com",
    "hurley.com",
    "reef.com",
    "vissla.com",
    "rivieraboardsport.com",
    "surfstitch.com",
    "surfdome.com",
    "snowscene.co.uk",
    "absolut-snow.co.uk",
    "surfboardshop.co.uk",
    "magicseaweed.com",
    "surfshack.com",
    "industrywests.com",
    "industrial-west.com",
    "craftandfolk.com",
    "crateandbarrel.com",
    "potterybarn.com",
    "williams-sonoma.com",
    "anthropologie.com",
    "freepeople.com",
    "urbanoutfitters.com",
    "cb2.com",
    "west-elm.com",
    "worldmarket.com",
    "pier1imports.com",
    "targetstyle.com",
    "walmart.com",
    "costco.com",
    "samsclub.com",
    "bedbathandbeyond.com",
    "homedepot.com",
    "lowes.com",
    "menards.com",
    "aceharware.com",
    "truvalue.com",
    "harborfreight.com",
    "northerntool.com",
    "globalindustrial.com",
    "zoro.com",
    "mscdirect.com",
    "grainger.com",
    "fastenal.com",
    "mcmaster.com",
    "enco.com",
    "littlemachineshop.com",
    "micromark.com",
    "horological.com",
    "ofrei.com",
    "riogrande.com",
    "oroamerica.com",
    "gesswein.com",
    "stuller.com",
    "firemountaingems.com",
    "dreamtimecreations.com",
    "createyourown.com",
    "craftaholicsanonymous.com",
    "scrapbook.com",
    "craftsuppliesusa.com",
    "yarn.com",
    "webs.com",
    "knitpicks.com",
    "etsy.com",
    "craftsy.com",
    "notonthehighstreet.com",
    "madeinkind.com",
    "folksy.com",
    "handmadeatlovebirds.com",
    "dotandbo.com",
    "zulily.com",
    "hautelook.com",
    "ideel.com",
    "gilt.com",
    "ruelala.com",
    "beyondtherack.com",
    "myntra.com",
    "jabong.com",
    "snapdeal.com",
    "flipkart.com",
    "amazon.in",
    "paytm.com",
    "meesho.com",
    "limeroad.com",
    "ajio.com",
    "tatacliq.com",
    "nykaa.com",
    "purplle.com",
    "mamaearth.in",
    "mcaffeine.com",
    "bodyshop.com",
    "thebodyshopusa.com",
    "aesop.com",
    "kiehlsusa.com",
    "origins.com",
    "clarins.com",
    "lancome.com",
    "yslbeauty.com",
    "giorgioarmanibeauty.com",
    "makeupforever.com",
    "narscosmetics.com",
    "urbandecay.com",
    "toofaced.com",
    "benefitcosmetics.com",
    "mabelline.com",
    "loreal-paris.com",
    "garnier.com",
    "neutrogena.com",
    "aveeno.com",
    "cerave.com",
    "cetaphil.com",
    "la-roche-posay.com",
    "vichy.com",
    "uriage.com",
    "eucerin.com",
    "nivea.com",
    "dove.com",
    "olayhome.com",
    "ponds.com",
    "lubriderm.com",
    "vaseline.com",
    "jergenslotions.com",
    "goldbound.com",
    "skinceuticals.com",
    "obagi.com",
    "eltamd.com",
    "zoskinhealth.com",
    "neostrata.com",
    "peterthomasroth.com",
    "sunday-riley.com",
    "herbivore-botanicals.com",
    "ursa-major.com",
    "madesafe.org",
    "100-pure.com",
    "primallypure.com",
    "annmariegianni.com",
    "acure.com",
    "tree-to-tub.com",
    "burtsbees.com",
    "tom-organic.com",
    "organyc.co.uk",
    "natracare.com",
    "thinx.com",
    "modibodi.com",
    "periodnirvana.com",
    "saalt.com",
    "diva-cup.com",
    "lunette.com",
    "pixybellacup.com",
    "intimina.com",
    "organicup.com",
    "femmecup.com",
]


# ── Fingerprinting (reuses logic from 01_build_targets.py) ───────────────────

async def _fingerprint(domain: str, client: httpx.AsyncClient) -> str | None:
    async def _homepage() -> str | None:
        for scheme in ("https", "http"):
            try:
                r = await client.get(
                    f"{scheme}://{domain}/",
                    follow_redirects=True,
                    timeout=TIMEOUT,
                )
                text = r.text.lower()
                hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
                if "cdn.shopify.com" in text:
                    return "shopify"
                if "x-shopify-stage" in hdrs or "x-shopify-shop-api-call-limit" in hdrs:
                    return "shopify"
                if ".myshopify.com" in str(r.url):
                    return "shopify"
                if "wp-content/uploads/" in text or "wp-includes/js/" in text:
                    return "wordpress"
                if 'name="generator" content="wordpress' in text:
                    return "wordpress"
                if "wordpress" in hdrs.get("x-powered-by", ""):
                    return "wordpress"
                return None
            except Exception:
                if scheme == "https":
                    continue
        return None

    async def _wp_login() -> bool:
        for scheme in ("https", "http"):
            try:
                r = await client.get(
                    f"{scheme}://{domain}/wp-login.php",
                    follow_redirects=True,
                    timeout=TIMEOUT,
                )
                if r.status_code == 200 and "wordpress" in r.text.lower():
                    return True
            except Exception:
                if scheme == "https":
                    continue
        return False

    async def _shopify_products() -> bool:
        for scheme in ("https", "http"):
            try:
                r = await client.get(
                    f"{scheme}://{domain}/products.json",
                    follow_redirects=True,
                    timeout=TIMEOUT,
                )
                if r.status_code == 200:
                    ct = r.headers.get("content-type", "").lower()
                    if "json" in ct:
                        body = r.text
                        if '"products"' in body or '"handle"' in body:
                            return True
            except Exception:
                if scheme == "https":
                    continue
        return False

    hp, wp, sf = await asyncio.gather(
        _homepage(), _wp_login(), _shopify_products(),
        return_exceptions=True,
    )
    if hp == "shopify" or sf is True:
        return "shopify"
    if hp == "wordpress" or wp is True:
        return "wordpress"
    return None


# ── Main ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Load already-found domains so we don't duplicate
    existing: set[str] = set()
    if OUT_CSV.exists():
        with open(OUT_CSV) as f:
            for row in csv.DictReader(f):
                existing.add(row["domain"].lower())

    # Deduplicate seed list
    candidates = []
    seen: set[str] = set()
    for d in SEED_DOMAINS:
        d = d.lower().strip()
        if d and d not in seen and d not in existing:
            seen.add(d)
            candidates.append(d)

    total = len(candidates)
    print(f"🌱 Seeding from {total} curated candidates ({len(existing)} already in targets.csv) …", flush=True)

    found   = {"shopify": 0, "wordpress": 0}
    results = []
    lock    = asyncio.Lock()
    counter = [0]
    sem     = asyncio.Semaphore(WORKERS)

    limits = httpx.Limits(
        max_connections=WORKERS + 20,
        max_keepalive_connections=WORKERS,
    )

    async def _worker(domain: str, client: httpx.AsyncClient) -> None:
        async with sem:
            platform = await _fingerprint(domain, client)
        async with lock:
            counter[0] += 1
            pct = counter[0] / total * 100
            if platform:
                found[platform] = found.get(platform, 0) + 1
                results.append((0, domain, platform))
                s = found.get("shopify", 0)
                w = found.get("wordpress", 0)
                print(
                    f"\r   [{counter[0]:>4}/{total}  {pct:4.0f}%]"
                    f"  Shopify {s:>3}  WordPress {w:>3}"
                    f"  {domain:<40}",
                    end="", flush=True,
                )

    async with httpx.AsyncClient(
        limits=limits,
        headers={"User-Agent": UA},
        follow_redirects=True,
    ) as client:
        tasks = [asyncio.create_task(_worker(d, client)) for d in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\n\n✅ Seed scan complete: {found}", flush=True)
    print(f"   Confirmed {len(results)} new targets", flush=True)

    if not results:
        print("   No new targets found in seed list.", flush=True)
        return

    # Append to existing targets.csv
    write_header = not OUT_CSV.exists()
    with open(OUT_CSV, "a", newline="") as fh:
        w = csv.writer(fh)
        if write_header:
            w.writerow(["rank", "domain", "platform"])
        w.writerows(results)

    print(f"📄 Appended {len(results)} seeded targets → {OUT_CSV}", flush=True)

    # Final count
    total_lines = sum(1 for _ in open(OUT_CSV)) - 1  # subtract header
    print(f"   Total targets in CSV: {total_lines}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
