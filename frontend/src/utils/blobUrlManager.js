/**
 * BlobUrlManager - Manages blob URLs lifecycle to prevent memory leaks
 *
 * This class ensures that all created blob URLs are properly cleaned up
 * when no longer needed, preventing memory leaks in long-running applications.
 */
export class BlobUrlManager {
  constructor() {
    this.urls = new Map()
  }

  /**
   * Creates a blob URL and tracks it for cleanup
   * @param {Blob|File} blob - The blob or file to create URL for
   * @param {string} key - Unique identifier for this URL
   * @returns {string} The created blob URL
   */
  createUrl(blob, key) {
    // Clean up existing URL for this key if any
    this.revokeUrl(key)

    const url = URL.createObjectURL(blob)
    this.urls.set(key, url)
    return url
  }

  /**
   * Revokes a specific blob URL
   * @param {string} key - The key of the URL to revoke
   */
  revokeUrl(key) {
    const url = this.urls.get(key)
    if (url) {
      URL.revokeObjectURL(url)
      this.urls.delete(key)
    }
  }

  /**
   * Revokes all tracked blob URLs
   */
  revokeAll() {
    for (const url of this.urls.values()) {
      URL.revokeObjectURL(url)
    }
    this.urls.clear()
  }

  /**
   * Gets a URL by key without creating a new one
   * @param {string} key - The key to look up
   * @returns {string|undefined} The URL if exists
   */
  getUrl(key) {
    return this.urls.get(key)
  }

  /**
   * Checks if a URL exists for a key
   * @param {string} key - The key to check
   * @returns {boolean} True if URL exists
   */
  hasUrl(key) {
    return this.urls.has(key)
  }

  /**
   * Gets the count of tracked URLs
   * @returns {number} Number of tracked URLs
   */
  get size() {
    return this.urls.size
  }
}
