import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/" },
    sitemap: "https://secchecker.cc/sitemap.xml",
    host: "https://secchecker.cc"
  };
}
