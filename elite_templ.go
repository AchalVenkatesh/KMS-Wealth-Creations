// Code generated by templ - DO NOT EDIT.

// templ: version: v0.2.747
package main

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import templruntime "github.com/a-h/templ/runtime"

func ElitePosts(posts map[string]Posts, elite string) templ.Component {
	return templruntime.GeneratedTemplate(func(templ_7745c5c3_Input templruntime.GeneratedComponentInput) (templ_7745c5c3_Err error) {
		templ_7745c5c3_W, ctx := templ_7745c5c3_Input.Writer, templ_7745c5c3_Input.Context
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templruntime.GetBuffer(templ_7745c5c3_W)
		if !templ_7745c5c3_IsBuffer {
			defer func() {
				templ_7745c5c3_BufErr := templruntime.ReleaseBuffer(templ_7745c5c3_Buffer)
				if templ_7745c5c3_Err == nil {
					templ_7745c5c3_Err = templ_7745c5c3_BufErr
				}
			}()
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var1 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var1 == nil {
			templ_7745c5c3_Var1 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<!doctype html><html id=\"body\" lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><meta http-equiv=\"Content-Security-Policy\" content=\"upgrade-insecure-requests\"><title>Elite Posts</title><link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"><link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin><script src=\"https://unpkg.com/htmx.org@1.9.12/dist/htmx.js\" integrity=\"sha384-qbtR4rS9RrUMECUWDWM2+YGgN3U4V4ZncZ0BvUcg9FGct0jqXz3PUdVpU1p0yrXS\" crossorigin=\"anonymous\"></script><link href=\"https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&amp;display=swap\" rel=\"stylesheet\"><link href=\"https://cdnjs.cloudflare.com/ajax/libs/lightbox2/2.11.3/css/lightbox.min.css\" rel=\"stylesheet\"><style>\r\n    * {\r\n      box-sizing: border-box;\r\n    }\r\n\r\n    body {\r\n      font-family: 'Montserrat', sans-serif;\r\n      margin: 0;\r\n      padding: 0;\r\n      background-color: #fff5d7;\r\n      color: #333;\r\n    }\r\n\r\n    header {\r\n      background-color: #343a40;\r\n      color: #fff;\r\n      padding: 1rem;\r\n      display: flex;\r\n      align-items: center;\r\n      justify-content: space-between;\r\n      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);\r\n      position: relative;\r\n    }\r\n\r\n    section {\r\n    display: block;\r\n    unicode-bidi: isolate;\r\n}\r\n\r\nfooter {\r\n  background-color: #343a40;\r\n  color: #fff;\r\n  padding: 1.25rem;\r\n  text-align: center;\r\n  margin-top: 2.5rem;\r\n}\r\n\r\n    .navbar {\r\n      display: flex;\r\n      justify-content: space-between;\r\n      align-items: center;\r\n      width: 100%;\r\n      padding: 0;\r\n    }\r\n\r\n   .logo {\r\n      padding: 20px;\r\n      max-width: 128px;\r\n      border-radius: 50%;\r\n      align-self: left;\r\n      margin-top: 0;\r\n      max-height: 128px;\r\n    }\r\n\r\n    .navbar .nav-content {\r\n      display: flex;\r\n      align-items: center;\r\n    }\r\n\r\n    .navbar .nav-links {\r\n      display: flex;\r\n      list-style: none;\r\n      margin: 0;\r\n      padding: 0;\r\n    }\r\n\r\n\r\n    .navbar .nav-links li {\r\n      margin-right: 1.25rem;\r\n    }\r\n\r\n    .navbar .nav-links li:last-child {\r\n      margin-right: 0;\r\n    }\r\n\r\n    .navbar .nav-links a {\r\n      color: #f2f2f2;\r\n      text-decoration: none;\r\n      font-size: 1rem;\r\n      padding: 0.875rem 1rem;\r\n    }\r\n\r\n    .navbar .nav-links a:hover {\r\n      background-color: #ddd;\r\n      color: #333;\r\n    }\r\n\r\n    .navbar .btn-signup,\r\n    .navbar .btn-login {\r\n      background-color: #4CAF50;\r\n      color: white;\r\n      padding: 0.625rem 1rem;\r\n      border: none;\r\n      border-radius: 0.25rem;\r\n      cursor: pointer;\r\n      font-size: 1rem;\r\n      margin-left: 0.625rem;\r\n    }\r\n\r\n    .navbar .btn:hover {\r\n      background-color: #45a049;\r\n    }\r\n\r\n    .navbar .dropdown-content {\r\n            display: none;\r\n            position: absolute;\r\n            padding-top: 5px;\r\n            background-color: #343a40;\r\n            min-width: 160px;\r\n            box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.2);\r\n            z-index: 1;\r\n            /* top: 100%; */\r\n        }\r\n\r\n        .navbar .dropdown-content a {\r\n            color: #fff;\r\n            padding: 0.875rem 1rem;\r\n            text-decoration: none;\r\n            display: block;\r\n        }\r\n\r\n        .navbar .dropdown-content a:hover {\r\n            background-color: #ddd;\r\n            color: #333;\r\n        }\r\n\r\n        .navbar .dropdown:hover .dropdown-content {\r\n            display:block;\r\n        }\r\n\r\n\r\n    .hamburger-menu {\r\n      display: none;\r\n      flex-direction: column;\r\n      cursor: pointer;\r\n    }\r\n\r\n    .hamburger-menu div {\r\n      width: 25px;\r\n      height: 3px;\r\n      background-color: #fff;\r\n      margin: 4px 0;\r\n      transition: 0.4s;\r\n    }\r\n\r\n    \r\n\r\n    #menu-toggle {\r\n      display: none;\r\n    }\r\n\r\n    .nav-links-mobile {\r\n      display: none;\r\n      flex-direction: column;\r\n      align-items: center;\r\n      width: 100%;\r\n      background-color: #343a40;\r\n      position: absolute;\r\n      top: 100%;\r\n      left: 0;\r\n    }\r\n\r\n    .nav-links-mobile a {\r\n      padding: 1rem;\r\n      width: 100%;\r\n      text-align: center;\r\n      border-top: 1px solid #444;\r\n    }\r\n\r\n    #menu-toggle:checked ~ .nav-links-mobile {\r\n      display: flex;\r\n    }\r\n\r\n    .about-us {\r\n    margin-bottom: 2.5rem;\r\n    background-color: #f8f9fa;\r\n    padding: 1.875rem;\r\n    border-radius: 0.625rem;\r\n    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);\r\n        max-width: 90vw;\r\n      margin: 2.5rem auto;\r\n    }\r\n\r\n    .about-us h1{\r\n        font-size: 4.5rem;\r\n        margin-bottom: 0;\r\n        padding-bottom: 0;\r\n        text-align: left;\r\n    }\r\n    .about-us h2{\r\n        margin-top: 10px;\r\n        text-align: left;\r\n    }\r\n\r\n    .about-us {\r\n    margin-bottom: 2.5rem;\r\n    background-color: #f8f9fa;\r\n    padding: 1.875rem;\r\n    border-radius: 0.625rem;\r\n    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);\r\n    max-width: 90vw;\r\n    margin: 2.5rem auto;\r\n}\r\n\r\n.about-content {\r\n    display: flex;\r\n    flex-direction: row;\r\n    justify-content: space-between;\r\n}\r\n\r\n.about-content .text {\r\n    flex: 1;\r\n    margin-left: 1.875rem; /* Adjust the spacing between text and image */\r\n}\r\n\r\n.about-content .image img{\r\n    flex-shrink: 0;\r\n     width: 300px;\r\n    height: auto;\r\n    max-width: 100%;\r\n}\r\n\r\n.about-us h2 {\r\n    margin-top: 0;\r\n    text-align: left;\r\n    size: 100%;\r\n}\r\n\r\nh1 {\r\n  font-size: 2rem;\r\n  margin-bottom: 0.625rem;\r\n}\r\n     p{\r\n        line-height: 2;\r\n     }\r\n\r\n     .company-info {\r\n    display: flex;\r\n    flex-direction: column;\r\n    padding-bottom: 1rem;\r\n    text-align: left;\r\n}\r\n\r\n.company-info h1{\r\n    margin-bottom: 0;\r\n}\r\n.company-info p{\r\n  margin-left: 0;\r\n}\r\n\r\n    @keyframes slideInFromLeft {\r\n      0% {\r\n        transform: translateX(-100%);\r\n        opacity: 0;\r\n      }\r\n      100% {\r\n        transform: translateX(0);\r\n        opacity: 1;\r\n      }\r\n    }\r\n\r\n    @media (max-width: 768px) {\r\n       .navbar .nav-links, .btn {\r\n        display: none;\r\n      }\r\n\r\n\r\n      /* .navbar {\r\n        flex-direction: column;\r\n        align-items: center;\r\n    } */\r\n\r\n     .hamburger-menu {\r\n    display: flex;\r\n    order: 3;\r\n    padding-left: 1rem;\r\n}\r\n.company-info {\r\n    order: 2;\r\n    padding-bottom: 1rem;\r\n    text-align: left;\r\n    flex-grow: 1;\r\n}\r\n.company-info h1{\r\n  text-align: left;\r\n}\r\n\r\n.company-info p{\r\n  display: none;\r\n}\r\n.logo {\r\n    order: 1;\r\n    max-width: 4rem;\r\n    margin-left: 0;\r\n    margin-right: 0;\r\n    padding-top: 1rem;\r\n}\r\n\r\n.about-content {\r\n    flex-direction: column;\r\n}\r\n\r\n.about-content .image {\r\n    order: -1;\r\n    margin-bottom: 1rem;\r\n}\r\n    }\r\n\r\n    @media (max-width: 480px) {\r\n      header {\r\n        padding: 0.625rem;\r\n      }\r\n\r\n      .navbar .nav-links li {\r\n        margin-right: 0.625rem;\r\n      }\r\n\r\n      .navbar .btn-login,\r\n      .navbar .btn-signup {\r\n        padding: 0.5rem 0.875rem;\r\n        font-size: 0.875rem;\r\n      }\r\n\r\n      .company-info h1{\r\n        text-align: center;\r\n      }\r\n      .company-info p{\r\n        text-align: center;\r\n      }\r\n    }\r\n</style></head><body><header>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = Navbar(elite).Render(ctx, templ_7745c5c3_Buffer)
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</header><section id=\"contact\" class=\"about-us\"><h2>Elite Posts</h2><div id=\"container\" class=\"container\">")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		templ_7745c5c3_Err = PostsTemplate(posts).Render(ctx, templ_7745c5c3_Buffer)
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</div></section><script>\r\n    async function calculateGrowth(element) {\r\n    console.log('Element:', element);\r\n    var rows = document.getElementsByTagName(\"tr\")\r\n    console.log(rows)\r\n    //const row = element.closest('tr');\r\n    for(let i=1; i<rows.length;i++){\r\n    var row = rows[i]\r\n    console.log('Row:', row);\r\n    \r\n    if (!row) {\r\n        console.error('No row found');\r\n        return;\r\n    }\r\n\r\n    const buyingPriceElement = row.querySelector('.buying-price');\r\n    const currentPriceElement = row.querySelector('.current-price');\r\n    const growthElement = row.querySelector('.growth');\r\n\r\n    console.log('Buying Price Element:', buyingPriceElement);\r\n    console.log('Current Price Element:', currentPriceElement);\r\n    console.log('Growth Element:', growthElement);\r\n\r\n    if (!buyingPriceElement || !currentPriceElement || !growthElement) {\r\n        console.error('Missing required elements');\r\n        return;\r\n    }\r\n\r\n\r\n    const buyingPrice = parseFloat(buyingPriceElement.textContent);\r\n    const currentPrice = parseFloat(currentPriceElement.textContent);\r\n\r\n    if (!isNaN(buyingPrice) && !isNaN(currentPrice)) {\r\n        const growth = currentPrice - buyingPrice;\r\n        const growthPercentage = (growth / buyingPrice) * 100;\r\n        growthElement.textContent = `${growth.toFixed(2)} (${growthPercentage.toFixed(2)}%)`;\r\n        \r\n        growthElement.style.color = growth > 0 ? 'green' : (growth < 0 ? 'red' : '');\r\n    } else {\r\n        growthElement.textContent = 'N/A';\r\n    }}\r\n}\r\n    </script><footer><style>\r\n      /* .contact-us{\r\n        text-align: left;\r\n      } */\r\n    </style><div class=\"contact-us\"><a href=\"/privacy\">Privacy policy</a><p>Contact Us</p><p>Email: <a href=\"mailto:info@arohanatradingacademy.org\">info@arohanatradingacademy.org</a></p><p>Phone: +91 8310383448</p><div class=\"social-media\"><a href=\"https://www.instagram.com/kmswealthcreations?igsh=MWRzc2R0a3hsbGYzaQ==\">Instagram</a> |  <a href=\"https://x.com/kmswcs\">Twitter</a></div></div><p>&copy; 2024 Arohana Trading Academy. All rights reserved.</p></footer></body></html>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		return templ_7745c5c3_Err
	})
}