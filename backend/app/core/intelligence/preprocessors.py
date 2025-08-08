"""Image preprocessing utilities for ML models."""

import numpy as np
from PIL import Image
from typing import Tuple, Optional, List, Dict, Any
import logging

# Try to import optional dependencies
try:
    from scipy import signal, ndimage

    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

try:
    import cv2

    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

logger = logging.getLogger(__name__)


class ImagePreprocessor:
    """Utilities for preprocessing images for ML inference."""

    # Pre-computed Sobel kernels for edge detection
    SOBEL_X = np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=np.float32)
    SOBEL_Y = np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]], dtype=np.float32)

    @staticmethod
    def resize_with_padding(
        image: Image.Image,
        target_size: Tuple[int, int],
        fill_color: Tuple[int, int, int] = (0, 0, 0),
    ) -> Image.Image:
        """Resize image to target size maintaining aspect ratio with padding.

        Args:
            image: Input PIL Image
            target_size: Target (width, height)
            fill_color: RGB color for padding

        Returns:
            Resized image with padding
        """
        # Calculate scaling factor
        width, height = image.size
        target_width, target_height = target_size

        scale = min(target_width / width, target_height / height)

        # Calculate new size
        new_width = int(width * scale)
        new_height = int(height * scale)

        # Resize image
        resized = image.resize((new_width, new_height), Image.Resampling.LANCZOS)

        # Create padded image
        padded = Image.new(image.mode, target_size, fill_color)

        # Calculate position to paste
        x = (target_width - new_width) // 2
        y = (target_height - new_height) // 2

        # Paste resized image
        padded.paste(resized, (x, y))

        return padded

    @staticmethod
    def normalize_image(
        image_array: np.ndarray,
        mean: Optional[List[float]] = None,
        std: Optional[List[float]] = None,
    ) -> np.ndarray:
        """Normalize image array for ML model input.

        Args:
            image_array: Image as numpy array (H, W, C)
            mean: Per-channel mean values
            std: Per-channel standard deviation values

        Returns:
            Normalized image array
        """
        # Default ImageNet normalization
        if mean is None:
            mean = [0.485, 0.456, 0.406]
        if std is None:
            std = [0.229, 0.224, 0.225]

        # Ensure float32
        normalized = image_array.astype(np.float32)

        # Scale to [0, 1] if needed
        if normalized.max() > 1.0:
            normalized = normalized / 255.0

        # Apply normalization
        for i in range(len(mean)):
            if i < normalized.shape[2]:
                normalized[:, :, i] = (normalized[:, :, i] - mean[i]) / std[i]

        return normalized

    @staticmethod
    def extract_image_patches(
        image: Image.Image, patch_size: int = 224, stride: int = 112
    ) -> List[np.ndarray]:
        """Extract overlapping patches from image for region-based analysis.

        Args:
            image: Input PIL Image
            patch_size: Size of each square patch
            stride: Stride between patches

        Returns:
            List of image patches as numpy arrays
        """
        width, height = image.size
        patches = []

        # Calculate number of patches
        num_x = (width - patch_size) // stride + 1
        num_y = (height - patch_size) // stride + 1

        for y in range(num_y):
            for x in range(num_x):
                # Extract patch
                left = x * stride
                top = y * stride
                right = min(left + patch_size, width)
                bottom = min(top + patch_size, height)

                patch = image.crop((left, top, right, bottom))

                # Ensure patch is correct size (pad if needed)
                if patch.size != (patch_size, patch_size):
                    padded = Image.new(image.mode, (patch_size, patch_size))
                    padded.paste(patch, (0, 0))
                    patch = padded

                patches.append(np.array(patch))

        return patches

    @staticmethod
    def prepare_for_edge_detection(image: Image.Image) -> np.ndarray:
        """Prepare image for edge detection algorithms.

        Args:
            image: Input PIL Image

        Returns:
            Preprocessed grayscale image array
        """
        # Convert to grayscale
        if image.mode != "L":
            gray = image.convert("L")
        else:
            gray = image

        # Convert to numpy array
        img_array = np.array(gray, dtype=np.uint8)

        # Apply Gaussian blur to reduce noise
        try:
            blurred = cv2.GaussianBlur(img_array, (5, 5), 1.0)
            return blurred
        except Exception:
            # If cv2 not available, return original
            return img_array

    @staticmethod
    def calculate_color_histogram(
        image: Image.Image, bins: int = 256
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Calculate color histogram for image analysis.

        Args:
            image: Input PIL Image
            bins: Number of histogram bins

        Returns:
            Tuple of (R, G, B) histograms
        """
        # Convert to RGB if needed
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Convert to numpy array
        img_array = np.array(image)

        # Calculate histograms
        hist_r = np.histogram(img_array[:, :, 0], bins=bins, range=(0, 256))[0]
        hist_g = np.histogram(img_array[:, :, 1], bins=bins, range=(0, 256))[0]
        hist_b = np.histogram(img_array[:, :, 2], bins=bins, range=(0, 256))[0]

        return hist_r, hist_g, hist_b

    @staticmethod
    def detect_dominant_colors(
        image: Image.Image, n_colors: int = 5, sample_size: int = 10000
    ) -> List[str]:
        """Extract dominant colors from image.

        Args:
            image: Input PIL Image
            n_colors: Number of dominant colors to extract
            sample_size: Number of pixels to sample

        Returns:
            List of hex color codes
        """
        try:
            from sklearn.cluster import KMeans

            # Convert to RGB
            if image.mode != "RGB":
                image = image.convert("RGB")

            # Resize for faster processing
            thumb_size = 100
            image.thumbnail((thumb_size, thumb_size), Image.Resampling.LANCZOS)

            # Convert to numpy array
            img_array = np.array(image)
            pixels = img_array.reshape(-1, 3)

            # Sample pixels if image is large
            if len(pixels) > sample_size:
                indices = np.random.choice(len(pixels), sample_size, replace=False)
                pixels = pixels[indices]

            # Perform k-means clustering
            kmeans = KMeans(n_clusters=n_colors, random_state=42, n_init=10)
            kmeans.fit(pixels)

            # Get cluster centers (dominant colors)
            colors = kmeans.cluster_centers_.astype(int)

            # Convert to hex
            hex_colors = []
            for color in colors:
                hex_color = "#{:02x}{:02x}{:02x}".format(color[0], color[1], color[2])
                hex_colors.append(hex_color)

            return hex_colors

        except ImportError:
            # Fallback if sklearn not available
            logger.warning("sklearn not available for color extraction")
            return []
        except Exception as e:
            logger.warning(f"Color extraction failed: {e}")
            return []

    @staticmethod
    def prepare_for_text_detection(image: Image.Image) -> np.ndarray:
        """Prepare image for text detection models.

        Args:
            image: Input PIL Image

        Returns:
            Preprocessed image array
        """
        # Convert to RGB
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Convert to numpy array
        img_array = np.array(image)

        # Resize to standard text detection input size
        # EAST text detector typically uses 320x320 or 512x512
        target_size = 320
        height, width = img_array.shape[:2]

        if height > target_size or width > target_size:
            scale = target_size / max(height, width)
            new_width = int(width * scale)
            new_height = int(height * scale)

            try:
                resized = cv2.resize(img_array, (new_width, new_height))

                # Pad to square
                if new_height < target_size:
                    pad_height = target_size - new_height
                    pad_top = pad_height // 2
                    pad_bottom = pad_height - pad_top
                    resized = cv2.copyMakeBorder(
                        resized,
                        pad_top,
                        pad_bottom,
                        0,
                        0,
                        cv2.BORDER_CONSTANT,
                        value=(0, 0, 0),
                    )
                elif new_width < target_size:
                    pad_width = target_size - new_width
                    pad_left = pad_width // 2
                    pad_right = pad_width - pad_left
                    resized = cv2.copyMakeBorder(
                        resized,
                        0,
                        0,
                        pad_left,
                        pad_right,
                        cv2.BORDER_CONSTANT,
                        value=(0, 0, 0),
                    )

                return resized
            except Exception:
                # Fallback to PIL if cv2 not available
                image = image.resize(
                    (target_size, target_size), Image.Resampling.LANCZOS
                )
                return np.array(image)

        return img_array

    @staticmethod
    def calculate_sharpness(image: Image.Image) -> float:
        """Calculate image sharpness score using Laplacian variance.

        Args:
            image: Input PIL Image

        Returns:
            Sharpness score (higher = sharper)
        """
        # Convert to grayscale
        if image.mode != "L":
            gray = image.convert("L")
        else:
            gray = image

        # Convert to numpy array
        img_array = np.array(gray, dtype=np.float32)

        try:
            # Calculate Laplacian
            laplacian = cv2.Laplacian(img_array, cv2.CV_64F)
            variance = laplacian.var()
            return float(variance)
        except Exception:
            # Fallback: use simple gradient calculation
            dx = np.diff(img_array, axis=1)
            dy = np.diff(img_array, axis=0)
            gradient_magnitude = np.sqrt(dx[:-1, :] ** 2 + dy[:, :-1] ** 2)
            return float(gradient_magnitude.var())

    @staticmethod
    def calculate_entropy_fast(gray_array: np.ndarray, bins: int = 256) -> float:
        """Calculate Shannon entropy optimized for speed.

        Args:
            gray_array: Grayscale image array
            bins: Number of histogram bins

        Returns:
            Shannon entropy value
        """
        # Downsample large images for speed
        if gray_array.size > 100000:
            gray_array = gray_array[::2, ::2]

        # Fast histogram calculation
        hist, _ = np.histogram(gray_array.flatten(), bins=bins, range=(0, 256))
        hist = hist[hist > 0]  # Remove zero bins for faster computation
        hist = hist / hist.sum()

        # Shannon entropy
        return -np.sum(hist * np.log2(hist))

    @staticmethod
    def detect_edges_sobel_optimized(
        gray_array: np.ndarray, threshold: int = 30
    ) -> Dict[str, float]:
        """Optimized Sobel edge detection for CPU.

        Args:
            gray_array: Grayscale image array
            threshold: Edge detection threshold

        Returns:
            Dictionary with edge metrics
        """
        # Downsample for speed if needed
        original_shape = gray_array.shape
        if gray_array.size > 100000:
            gray_array = gray_array[::2, ::2]

        # Apply Sobel filters using separable convolution (faster)
        if CV2_AVAILABLE:
            edges_x = cv2.Sobel(gray_array, cv2.CV_32F, 1, 0, ksize=3)
            edges_y = cv2.Sobel(gray_array, cv2.CV_32F, 0, 1, ksize=3)
        elif SCIPY_AVAILABLE:
            # Fallback to scipy
            edges_x = signal.convolve2d(
                gray_array, ImagePreprocessor.SOBEL_X, mode="valid", boundary="symm"
            )
            edges_y = signal.convolve2d(
                gray_array, ImagePreprocessor.SOBEL_Y, mode="valid", boundary="symm"
            )
        else:
            # Manual convolution fallback
            edges_x = ImagePreprocessor._manual_convolve2d(
                gray_array, ImagePreprocessor.SOBEL_X
            )
            edges_y = ImagePreprocessor._manual_convolve2d(
                gray_array, ImagePreprocessor.SOBEL_Y
            )

        # Calculate edge magnitude
        edge_magnitude = np.sqrt(edges_x**2 + edges_y**2)

        # Calculate metrics
        edge_pixels = np.sum(edge_magnitude > threshold)
        total_pixels = edge_magnitude.size
        edge_density = edge_pixels / total_pixels if total_pixels > 0 else 0

        # Detect straight edges (horizontal/vertical)
        horizontal_strength = np.mean(np.max(np.abs(edges_x), axis=1))
        vertical_strength = np.mean(np.max(np.abs(edges_y), axis=0))

        # Edge orientation histogram for detecting regular patterns
        edge_angles = np.arctan2(edges_y, edges_x)
        angle_hist, _ = np.histogram(edge_angles[edge_magnitude > threshold], bins=8)
        angle_uniformity = np.std(angle_hist) / (np.mean(angle_hist) + 1e-6)

        return {
            "edge_density": float(edge_density),
            "horizontal_strength": float(horizontal_strength),
            "vertical_strength": float(vertical_strength),
            "edge_straightness": float(
                (horizontal_strength + vertical_strength)
                / (original_shape[0] + original_shape[1])
            ),
            "angle_uniformity": float(angle_uniformity),
        }

    @staticmethod
    def analyze_color_distribution(
        image: Image.Image, sample_rate: float = 0.1
    ) -> Dict[str, Any]:
        """Analyze color distribution for content classification.

        Args:
            image: PIL Image
            sample_rate: Fraction of pixels to sample

        Returns:
            Dictionary with color metrics
        """
        # Convert to RGB if needed
        if image.mode != "RGB":
            image = image.convert("RGB")

        img_array = np.array(image)

        # Sample pixels for efficiency
        if img_array.size > 100000:
            flat_pixels = img_array.reshape(-1, 3)
            n_samples = int(len(flat_pixels) * sample_rate)
            indices = np.random.choice(len(flat_pixels), n_samples, replace=False)
            sampled_pixels = flat_pixels[indices]
        else:
            sampled_pixels = img_array.reshape(-1, 3)

        # Calculate color metrics
        unique_colors = len(np.unique(sampled_pixels, axis=0))
        color_variance = float(np.var(sampled_pixels))

        # Color channel statistics
        r_mean, g_mean, b_mean = np.mean(sampled_pixels, axis=0)
        r_std, g_std, b_std = np.std(sampled_pixels, axis=0)

        # Detect grayscale tendency
        gray_diff = np.abs(sampled_pixels[:, 0] - sampled_pixels[:, 1]) + np.abs(
            sampled_pixels[:, 1] - sampled_pixels[:, 2]
        )
        grayscale_ratio = np.sum(gray_diff < 10) / len(sampled_pixels)

        return {
            "unique_colors": unique_colors,
            "color_variance": color_variance,
            "channel_means": [float(r_mean), float(g_mean), float(b_mean)],
            "channel_stds": [float(r_std), float(g_std), float(b_std)],
            "grayscale_ratio": float(grayscale_ratio),
            "is_likely_grayscale": grayscale_ratio > 0.95,
        }

    @staticmethod
    def detect_ui_patterns(gray_array: np.ndarray) -> Dict[str, float]:
        """Detect UI patterns common in screenshots.

        Args:
            gray_array: Grayscale image array

        Returns:
            Dictionary with UI pattern metrics
        """
        h, w = gray_array.shape

        # Detect horizontal lines (common in UIs)
        horizontal_projection = np.mean(gray_array, axis=1)
        horizontal_edges = np.abs(np.diff(horizontal_projection))
        horizontal_lines = np.sum(horizontal_edges > np.std(horizontal_edges) * 2)

        # Detect vertical lines
        vertical_projection = np.mean(gray_array, axis=0)
        vertical_edges = np.abs(np.diff(vertical_projection))
        vertical_lines = np.sum(vertical_edges > np.std(vertical_edges) * 2)

        # Detect rectangular regions (buttons, text boxes)
        # Simplified approach: look for regions with consistent borders
        block_size = 32
        rect_score = 0

        for y in range(0, h - block_size, block_size // 2):
            for x in range(0, w - block_size, block_size // 2):
                block = gray_array[y : y + block_size, x : x + block_size]

                # Check if block has strong edges on all sides
                top_edge = np.mean(np.abs(np.diff(block[0, :])))
                bottom_edge = np.mean(np.abs(np.diff(block[-1, :])))
                left_edge = np.mean(np.abs(np.diff(block[:, 0])))
                right_edge = np.mean(np.abs(np.diff(block[:, -1])))

                # Check interior uniformity
                interior = block[2:-2, 2:-2]
                interior_variance = np.var(interior)

                # High edge strength + low interior variance = likely UI element
                if (
                    top_edge + bottom_edge + left_edge + right_edge
                ) > 40 and interior_variance < 100:
                    rect_score += 1

        total_blocks = ((h - block_size) // (block_size // 2)) * (
            (w - block_size) // (block_size // 2)
        )
        rect_ratio = rect_score / max(total_blocks, 1)

        return {
            "horizontal_lines": float(horizontal_lines / h),
            "vertical_lines": float(vertical_lines / w),
            "rectangular_regions": float(rect_ratio),
            "ui_score": float(
                (horizontal_lines / h + vertical_lines / w + rect_ratio) / 3
            ),
        }

    @staticmethod
    def calculate_texture_metrics(gray_array: np.ndarray) -> Dict[str, float]:
        """Calculate texture metrics for distinguishing photos from graphics.

        Args:
            gray_array: Grayscale image array

        Returns:
            Dictionary with texture metrics
        """
        # Local Binary Pattern (simplified version)
        h, w = gray_array.shape

        # Calculate gradients in multiple directions
        gradients = []

        # Horizontal and vertical gradients
        if h > 1 and w > 1:
            grad_h = np.abs(np.diff(gray_array, axis=1))
            grad_v = np.abs(np.diff(gray_array, axis=0))
            gradients.extend([grad_h.mean(), grad_v.mean()])

            # Diagonal gradients
            diag1 = np.abs(gray_array[1:, 1:] - gray_array[:-1, :-1])
            diag2 = np.abs(gray_array[1:, :-1] - gray_array[:-1, 1:])
            gradients.extend([diag1.mean(), diag2.mean()])

        # Texture uniformity (lower = more uniform)
        texture_variance = np.var(gradients) if gradients else 0

        # High-frequency content (indicates natural textures)
        if CV2_AVAILABLE and gray_array.size < 1000000:  # Limit size for performance
            # Use Laplacian for high-frequency detection
            laplacian = cv2.Laplacian(gray_array, cv2.CV_32F)
            high_freq_energy = np.var(laplacian)
        else:
            # Simplified high-frequency detection
            kernel = np.array([[0, -1, 0], [-1, 4, -1], [0, -1, 0]], dtype=np.float32)
            if gray_array.shape[0] > 3 and gray_array.shape[1] > 3:
                if SCIPY_AVAILABLE:
                    high_freq = signal.convolve2d(gray_array, kernel, mode="valid")
                else:
                    high_freq = ImagePreprocessor._manual_convolve2d(gray_array, kernel)
                high_freq_energy = np.var(high_freq)
            else:
                high_freq_energy = 0

        return {
            "texture_complexity": float(np.mean(gradients)) if gradients else 0,
            "texture_variance": float(texture_variance),
            "high_frequency_energy": float(high_freq_energy),
            "is_smooth": float(texture_variance) < 10,  # Likely illustration/screenshot
        }

    @staticmethod
    def _manual_convolve2d(image: np.ndarray, kernel: np.ndarray) -> np.ndarray:
        """Manual 2D convolution implementation for when scipy is not available.

        Args:
            image: Input image array
            kernel: Convolution kernel

        Returns:
            Convolved image array
        """
        # Get dimensions
        i_height, i_width = image.shape
        k_height, k_width = kernel.shape

        # Calculate output dimensions
        o_height = i_height - k_height + 1
        o_width = i_width - k_width + 1

        # Initialize output
        output = np.zeros((o_height, o_width), dtype=np.float32)

        # Perform convolution
        for y in range(o_height):
            for x in range(o_width):
                # Extract region
                region = image[y : y + k_height, x : x + k_width]
                # Element-wise multiply and sum
                output[y, x] = np.sum(region * kernel)

        return output
