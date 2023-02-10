const http = require("https");

(async () => {
  for (let i = 0; i < 5; i++) {
    const res = await new Promise((resolve, reject) =>
      http.get(
        `${process.env.MEILISEARCH_HOST_URL}/tasks?statuses=enqueued,processing`,
        {
          headers: {
            Authorization: `Bearer ${process.env.MEILISEARCH_API_KEY}`,
          },
        },
        (res) => {
          let chunks_of_data = [];
          res.on("data", (d) => chunks_of_data.push(d));
          res.on("error", (error) => {
            reject(error);
          });
          res.on("end", () =>
            resolve(Buffer.concat(chunks_of_data).toString())
          );
        }
      )
    );

    const json = JSON.parse(res);

    if (json["results"] instanceof Array && json["results"].length == 0) return;

    await new Promise((resolve) => setTimeout(resolve, 10000));
  }

  throw "Meilisearch instance still has enqueued or processing tasks";
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
