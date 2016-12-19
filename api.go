package main

import (
    "fmt"
    "flag"
    "net/http"
    "github.com/julienschmidt/httprouter"
    "github.com/SermoDigital/jose/jws"
    "gopkg.in/square/go-jose.v1"
    "encoding/json"
//    "bytes"
    "io/ioutil"
    "log"
    "strings"
)


var JWKset jose.JsonWebKeySet

var (
	httpAddr = flag.String("http", ":3000", "Listen address")
)

func ParseTokenHandler(rw http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    var kid string
    j, err := jws.ParseFromHeader(r, jws.Compact)
    //j, err := jws.ParseJWSFromRequest(r)
	if err != nil {
		fmt.Println("Parse Error", err)
	} else {
		//fmt.Println("Parsed Successfully %+v", j)
		//c := j.Claims()
		//fmt.Println("Parsed Successfully %+v", c)
		//if j.IsJWT() {


		//c := j.Claims()
			//fmt.Println("Good %+v", c)
		//}
		h := j.Protected()
		if h != nil {
			fmt.Println("Kid:  ", h["kid"]);
			kid = h["kid"].(string)
                }
	}
    // Validate token here...
    // j.Validate(rsaPublic, crypto.SigningMethodRS256)
	//if err != nil {
	//	if j.IsJWT() {
	//	fmt.Fprint(rw, "Protected!\n")
	//	}
	//} else {
	//	fmt.Fprint(rw, "Protected could not read JWT!\n")
	//}


	if ah := r.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:7]) == "BEARER " {
			//return jwt.Parse(ah[7:], keyFunc)
			object, err := jose.ParseSigned(ah[7:])
			if err != nil {
    				panic(err)
			} else {
				matchingKeys := JWKset.Key(kid)
				//output, err := object.Verify(JWKset.Keys[0].Key)
				output, err := object.Verify(matchingKeys[0].Key)
				if err != nil {
    					panic(err)
				}
				fmt.Println("parssed key success with square")
				fmt.Printf(string(output))
			}
		}
	}


	rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
	rw.WriteHeader(200)
	strJson, _ := json.Marshal(struct {
		Msg string `json:"msg"`
	}{
		Msg: "You have accessed the protected Resource",
	})
	rw.Write(strJson)

}


func main() {
    var url = "https://springwiz.oktapreview.com/oauth2/v1/keys"
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
	log.Fatal(err)
    }
    req.Header.Add("Accept", `application/json`)
    req.Header.Add("Content-Type", `application/json`)
    var client = &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
	log.Fatal(err)
    }
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
	log.Fatal(err)
    }
    if resp.StatusCode == http.StatusOK {
	err := json.Unmarshal(body, &JWKset)
	if err != nil {
	    log.Fatal(err)
	}
    } else {
	fmt.Println("Http Error")
    }
    resp.Body.Close()

    fmt.Println("number of keys", len(JWKset.Keys))
    fmt.Println(JWKset.Keys[0])

    r := httprouter.New()
    r.GET("/protected", ParseTokenHandler)
    http.ListenAndServe(*httpAddr, r)
}
