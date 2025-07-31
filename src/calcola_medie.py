import pandas as pd

# === Leggi il contenuto del file come testo ===
with open('dati_tempi.csv', 'r') as f:
    raw = f.read()

# === Dividi in blocchi separati da righe vuote ===
blocchi = [b.strip() for b in raw.strip().split('\n\n') if b.strip()]

# === Liste per i totali per gruppo ===
software_totali = []
device_totali = []

# === Elabora ogni gruppo ===
for i, blocco in enumerate(blocchi, 1):
    from io import StringIO
    df = pd.read_csv(StringIO(blocco), header=None, names=['ip', 'tempo_autent', 'tempo_appl', 'tempo_device'])

    # Calcola somma totale per gruppo
    software_sum = (df['tempo_autent'] + df['tempo_appl']).sum()
    device_sum = df['tempo_device'].sum()

    software_totali.append(software_sum)
    device_totali.append(device_sum)

    print(f"Gruppo {i}: somma software = {software_sum:.3f} s, somma device = {device_sum:.3f} s")

# === Calcola media tra i gruppi ===
media_software_tra_gruppi = sum(software_totali) / len(software_totali)
media_device_tra_gruppi = sum(device_totali) / len(device_totali)

print("\n=== Media tra i gruppi ===")
print(f"Media somme software: {media_software_tra_gruppi:.3f} s")
print(f"Media somme device:   {media_device_tra_gruppi:.3f} s")

# === Salva su CSV ===
df_out = pd.DataFrame({
    'gruppo': list(range(1, len(software_totali)+1)),
    'somma_software': software_totali,
    'somma_device': device_totali
})
df_out.to_csv('somme_gruppi.csv', index=False)
