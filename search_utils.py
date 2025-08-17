from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer('all-MiniLM-L6-v2')  # Efficient and accurate

def filter_by_semantic_similarity(query, listings, threshold=0.4):
    if not query or not listings:
        return listings

    query_embedding = model.encode(query, convert_to_tensor=True)
    descriptions = [listing.description for listing in listings]
    desc_embeddings = model.encode(descriptions, convert_to_tensor=True)

    similarities = util.cos_sim(query_embedding, desc_embeddings)[0]

    results = []
    for i, score in enumerate(similarities):
        if score >= threshold:
            results.append(listings[i])
    return results
