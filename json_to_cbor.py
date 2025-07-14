"""
json_to_cbor.py

Usage:
    1. Edit the 'json_input' variable with your JSON string.
    2. Run: python3 json_to_cbor.py
    3. The CBOR bytes will be saved to 'output.cbor' and printed as hex.

Requires:
    pip install cbor2
"""
import json
import cbor2

def keys_to_int(obj):
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            try:
                k2 = int(k)
            except (ValueError, TypeError):
                k2 = k
            new[k2] = keys_to_int(v)
        return new
    elif isinstance(obj, list):
        return [keys_to_int(i) for i in obj]
    else:
        return obj

photo1 = "52494646020300005745425056503820f6020000b01c009d012aa000c8003f69aacb5bb3bfbd2babd35aa3f02d09672d800aa7c3be99c9521514741d9446a41c1ce47180e652c8d60370a232a534b2bc653e0c075dd642b47780c652cfe1a11c59dbb87123ed9b4447577829d771d0cb7e383da6e24104fd32c24450c29a232749a3d1ef621211a00a6a99e1d92a4eaa2055179a8afb6e70c677a9edc7e09102fbf7368344fe382e8111ba4e39e7a5740155e0ee2144569dbb1a92035b8f42e0126416238df9b0d914f2159e28f050b501329f7713312be0c19ab032b4170fc0f634e6ed1f7be6fb379823b55e2ff8a6d2b05e40bc8db458c649fb375ed2ef84700000feea78110fde6f759e8787a50b0d1f3f3a0548a84b947cc2c16380dc7106974822e09b5ca0afd13547c984a38d407be05feeb8a37270e0ea19ef0f9bef7ea1d8788938f6d0780d7326624205a395cad3131a4ba060cd122bf1396eb94b0c7e36ff92b585af5a8ab3043d45c08f151876e31217a5835724e193018b6982dea57d20057f2fa579bf44bebf000296cb23436655d6371cfb1ebd7dc8f6fec5e523ea83af0031dc896f315508dfb38d373017d13bc820450ded245a65f42014a9cf09e00337acc4be1721891e5478c195e4e31d1d0d264357d168f6e2b6cddb85aab2d52450134f7d3e08c6e72fba4ad1610ec2d36c55e6aa62394440a10b712d622e4a4a28b82f7f0a347f7b51b3417ef6949d8447d7f488a421a03119fd2550d1dd62b3c368640a7cd64051115273ec1d09921dd19e2dc0c29afd2d74991de2c9aaecc6e33607ab0278a0913f6730410582564d6b9d68d5eb2c1b67eec36034462a8a3ffc0951f27b8223da9185e5214003fe04f7479acc72a503d18482bea4849e9d824707a7bc5440db095feb3d9b59d2fdf7991ced527dfa379c5ae0b78c6a291a1508d8dd84df656262d7bea50ea0c2fbcb71edd8748c45c568ba079d355e6f1ae095f62b9d679a7925e007e2d0562a8578b2c6c090eb40249c27aa25f6469e8da60a8d6450f062ccb3406eeb0517869d6b2ce97462ca0ec566a8bfbc5a63bd9519edf6180000"
photo2 = "3d8a7e81527262399d5bad6e1c5d7198493259557b6d597e430041468163557a345382786862af593f6491c8aa7f7971853984a6a79886166891478970575f63c37f4d3dab44686f2a291685ff9f198b6560838866775471b2756bb06a7282735f60406173636e9738a780834f74446fac1bb5a877a37c7a797326548f4f7d899a3da5be1d24d43e"

data = {
    1: -7,
    4: "4",
    169: {
        4: "Mikias Estifanos Paulos",
        8: "19971007",
        9: 1,
        12: "09239979918",
        13: "Ethiopia",
        62: [
            {0: photo1, 1: 0},
            {0: photo2, 1: 1}
        ]
    }
}

cbor_bytes = cbor2.dumps(data)
print(cbor_bytes.hex())

with open('output.cbor', 'wb') as f:
    f.write(cbor_bytes) 