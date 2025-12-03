# Dataset Restructure Analysis

## Proposed Structure

1. **Domain-Only Dataset**: Features extracted ONLY from domain component
   - Full URL column (reference only, not used for features)
   - Domain component column (all features derive from this)

2. **Path-Only Dataset**: Features extracted ONLY from path component
   - Full URL column (reference only, not used for features)
   - Path component column (all features derive from this)

3. **Combined Dataset**: Features from both domain and path
   - Full URL column (reference only, not used for features)
   - Domain component column
   - Path component column

## 🚨 RED FLAGS & ISSUES

### 1. **Feature Naming Conflicts**

Currently, many features are calculated on the **full URL** but named generically:

**Problem Features:**
- `url_length` - Currently full URL length, but in domain-only should be domain length
- `url_entropy` - Currently full URL entropy, but in domain-only should be domain entropy
- `num_dots`, `num_hyphens`, `num_underscores` - Currently counted across full URL
- `digit_ratio`, `letter_ratio`, `special_char_ratio` - Currently calculated on full URL
- `has_at_symbol` - Currently checked in full URL
- `has_suspicious_keywords` - Currently checked in full URL
- `has_shortener` - Currently checked in full URL
- `has_obfuscation`, `num_obfuscated_chars`, `obfuscation_ratio` - Currently full URL

**Solution Needed:**
- Rename features to be component-specific OR
- Create separate extraction methods for domain-only vs path-only

### 2. **Query Parameters - Where Do They Go?**

Query parameters (`?key=value`) are **separate from path**:
- Currently: `query_length`, `num_params`, `has_suspicious_params`
- Question: Should query params be:
  - In domain-only dataset? (No, they're not domain)
  - In path-only dataset? (Maybe, they're URL structure)
  - Separate component? (Most accurate)

**Recommendation:** Query params should be in path-only dataset since they're part of URL structure, not domain.

### 3. **Protocol/HTTPS Features**

Features like `uses_https`, `uses_http` are protocol-level, not domain or path:
- Where should these go?
- Domain-only? (Domain includes protocol in some contexts)
- Combined only?

### 4. **Brand Features**

Some brand features span both domain and path:
- `brand_similarity_path` - Path-specific ✓
- `brand_in_path_or_query` - Path-specific ✓
- `brand_in_registered_domain` - Domain-specific ✓
- `brand_similarity_registered` - Domain-specific ✓
- `brand_mismatch` - Could involve both

### 5. **Breaking Changes**

This restructure will:
- ❌ Break existing models (feature names/order will change)
- ❌ Require retraining all models
- ❌ Require updating extension code
- ❌ Require updating all training scripts
- ❌ Require updating weighted predictor

### 6. **Feature Extraction Logic**

Need to create **three separate extraction methods**:
```python
extract_domain_features(domain)  # Only domain
extract_path_features(path, query)  # Only path + query
extract_combined_features(domain, path, query)  # Both
```

Current `extract_features(url)` calculates everything from full URL.

## ✅ RECOMMENDED APPROACH

### Option A: Component-Specific Feature Extraction (Your Proposal)

**Pros:**
- Clean separation of concerns
- No feature leakage between datasets
- Clearer model interpretation

**Cons:**
- Major refactoring required
- All models need retraining
- Feature naming needs careful design

**Implementation:**
1. Create `extract_domain_features(domain)` method
2. Create `extract_path_features(path, query)` method  
3. Create `extract_combined_features(domain, path, query)` method
4. Update dataset generation scripts
5. Retrain all models
6. Update extension code

### Option B: Keep Current Structure, Fix Feature Leakage

**Pros:**
- Minimal changes
- Models stay compatible
- Easier migration

**Cons:**
- Less clean separation
- Some features still aggregate

**Implementation:**
- Rename aggregate features to be explicit (e.g., `url_length` → `full_url_length`)
- Keep domain-only features truly domain-only
- Keep path-only features truly path-only

## 🎯 RECOMMENDATION

**Proceed with Option A** (your proposal) BUT:

1. **Create clear feature naming convention:**
   - Domain-only: `domain_length`, `domain_entropy`, `domain_digit_ratio`, etc.
   - Path-only: `path_length`, `path_entropy`, `path_digit_ratio`, etc.
   - Combined: Both sets

2. **Handle query parameters:**
   - Include in path-only dataset (they're URL structure, not domain)

3. **Handle protocol features:**
   - Include in domain-only (protocol is domain-level)
   - OR create separate "URL structure" features

4. **Migration plan:**
   - Phase 1: Create new extraction methods
   - Phase 2: Generate new datasets
   - Phase 3: Retrain models
   - Phase 4: Update extension
   - Phase 5: Test thoroughly

## ⚠️ CRITICAL DECISIONS NEEDED

1. **Query parameters:** Domain-only, Path-only, or Separate?
2. **Protocol (HTTPS/HTTP):** Domain-only or Combined only?
3. **Feature naming:** Prefix all with component? (e.g., `domain_url_length` vs `path_url_length`)
4. **Backward compatibility:** Keep old datasets or full migration?

