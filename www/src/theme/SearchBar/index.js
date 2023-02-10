import React, {useEffect} from "react";
import "./style.css";
import "meilisearch-docsearch/css";

export default function Component() {
  useEffect(() => {
    const lang = document.querySelector("html").lang || "en";

    const docsearch = require("meilisearch-docsearch").default;
    const destroy = docsearch({
      host: "https://ms-2bfa4e48f68a-1927.sfo.meilisearch.io",
      apiKey:
        "25468d493103c5be6fc7d1f83026946f56765599aaf417ddb5104921fc8e9120",
      indexUid: "docs-v1",
      container: "#docsearch",
      //   searchParams: {filter: [`lang = ${lang}`]},
    });

    return () => destroy();
  }, []);

  return <div id="docsearch" />;
}
