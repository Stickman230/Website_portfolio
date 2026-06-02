import pickle, sklearn, base64

### This model takes in words and transforms them into 238 numerical categories that are then classified into 8 different classes
### We are looking for 3 words that will make up the ZiTF{} flag: ZiTF{word1_word2_word3}

### !!!!!!! WARNING: pickle files can execute code when loaded. Only load pickle files in a safe CTF/lab environment. !!!!!!

path = "gravitational_model2.pkl"

with open(path, "rb") as f:
    data = pickle.load(f)

model = data["model"]
vectorizer = data["vectorizer"]

print("General Model content:", model.__dict__.items())  ### This initially shows 2 things: a 'secret' classification class and a custom 'galaxy_' attribute

classes, model_shape = model.classes_, model.coef_.shape
print("\nPossible classification classes of this model", classes)  ### Classes = ['black_hole' 'galaxy' 'gas_giant' 'ice_giant' 'secret' 'star' 'super_earth' 'terrestrial_planet']
print("\nNumber of classes and features per class:", model_shape)  ### 8 rows, 238 columns

sec_index = list(classes).index("secret")
print("\nIndex of the secret class:", sec_index)  ### With this index we can go and check the coefficients for this class

coef = model.coef_[sec_index]
print("\nModel class 'secret' features coefficient:", coef)  ### Here one particularly stands out, '5.336722'; now let's check its related vocabulary in the vectorizer

print("\nThis is the whole vocabulary classification for this model", vectorizer.vocabulary_)  ### Too much to process for my small brain, let's sort this

sorted_vocab = dict(sorted(vectorizer.vocabulary_.items(), key=lambda item: item[1]))
comparison = []

for k, v in sorted_vocab.items():
    comparison.append((sorted_vocab[k], k, float(coef[v])))

biggest_coef_sorted = sorted(comparison, key=lambda x: x[2], reverse=True)[:10]
print("\nWhat are the biggest weights for the secret class", biggest_coef_sorted)  ### "banana" comes out on top by a lot
### Such a major weight difference is not a coincidence, so we assume that one of the words is: banana

### Now we come back to the bizarre attribute 'galaxy_'
galaxy_output = model.galaxy_
b64decoded_galaxy = base64.b64decode(galaxy_output).decode("utf-8")
print("\nWe check out the contents of 'galaxy_':", model.galaxy_, "and decode it from base64:", b64decoded_galaxy)  ### "love" is the decoded string from this custom artifact value

### Now we attempt to find the third word of our flag; let's look closer at our classifier classes
print(classes)

for i in range(len(classes)):
    # print(model.coef_[i])  ### Nothing stands out too much here, too many numbers. Let's attempt something different
    for j in range(len(model.coef_[0])):
        myint_model = int(model.coef_[i][j])

        if myint_model > 1:
            print("\nIn class:", classes[i], "value:", myint_model)  ### That seems promising, there are some very unusual positive integers in class super_earth

### In class super_earth, we found these interesting values: 99, 104, 105, 109, 112, 97, 110, 122, 101, 101
### Throw that in CyberChef (https://gchq.github.io/CyberChef/) and mess with them until you realise that it is ASCII encoding

### 99 104 105 109 112 97 110 122 101 101
### c  h   i   m   p   a  n   z   e   e
### Decoding these gives us the 3rd word, "chimpanzee"

'''
First word is found in secret class coefficients = banana
Second word is the galaxy artifact value (bG92ZQ==) decoded from base64 = love
Third word is found in the super_earth classification coefficients and gives us = chimpanzee

If we use the words to make a grammatically correct concatenation, we order it as: chimpanzee love banana

The flag is ZiTF{chimpanzee_love_banana}
'''
