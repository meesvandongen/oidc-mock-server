import { createServer } from "./server";

const server = await createServer({});

server.listen(3000, () => {
	console.log("Server listening on port 3000");
});
