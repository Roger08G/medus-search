# **DisclosureSearch**

Herramienta para buscar información likeada (filtraciones, secretos, tokens, etc.) en el contenido de páginas web.

## **Instalación:**

```bash
pip3 install aiohttp beautifulsoup4 colorama
```

## **Uso:**

```bash
python3 setup.py -o <archivo_de_dominios> -d <profundidad>
```

 ["-o", "--input"]: Archivo de entrada con dominios/subdominios
 ["-d", "--depth"]: Profundidad máxima para el crawl (default: 2)

- *Ejemplo:*

```bash
python3 setup.py -o valid_domains.txt -d 2
```
*Nota:* Los resultados se guardarán en la carpeta ``output/``.

