func (h *httpStream) run() {
	// Wrap the existing reader with the logging reader
	logReader := &loggingReader{originalReader: &h.r}
	buf := bufio.NewReader(logReader)

	// List of allowed URI paths
	allowedPaths := []string{"/v5/SaveOrder"}

	for {
		// Read bytes until we find the start of an HTTP request (e.g., "POST /v5/SaveOrder HTTP/1.1")
		var buffer bytes.Buffer

		for {
			b, err := buf.ReadByte()
			if err == io.EOF {
				// This indicates the end of the stream.
				return
			} else if err != nil {
				log.Println("Error reading stream", h.net, h.transport, ":", err)
				continue // Skip to the next iteration if there's an error
			}
			buffer.WriteByte(b)
			if buffer.Len() >= 4 && buffer.String()[buffer.Len()-4:] == "\r\n\r\n" {
				break
			}
		}

		// Check if the start of the request matches "POST /v5/SaveOrder"
		requestStart := buffer.String()
		if strings.HasPrefix(requestStart, "POST /v5/SaveOrder") {
			// Now that we found the start of the HTTP request, create a new HTTP request
			req, reqErr := http.ReadRequest(bufio.NewReader(strings.NewReader(requestStart))
			if reqErr != nil {
				log.Println("Error reading HTTP request:", reqErr)
				buffer.Reset()
				continue // Skip to the next iteration if there's an error
			}

			reqSourceIP := h.net.Src().String()
			reqDestionationPort := h.transport.Dst().String()

			// Check if the request method is POST and the request URI matches the desired paths
			if req.Method == "POST" {
				body, bErr := ioutil.ReadAll(req.Body)
				if bErr != nil {
					continue // Skip to the next iteration if there's an error
				}
				req.Body.Close()
				log.Println("Request Body:", string(body)) // Log the request body
				go forwardRequest(req, reqSourceIP, reqDestionationPort, body)
			}
		}
	}
}
