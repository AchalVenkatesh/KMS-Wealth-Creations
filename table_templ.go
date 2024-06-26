// Code generated by templ - DO NOT EDIT.

// templ: version: v0.2.707
package main

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import "context"
import "io"
import "bytes"

func PostsTemplate(posts map[string]Posts) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, templ_7745c5c3_W io.Writer) (templ_7745c5c3_Err error) {
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templ_7745c5c3_W.(*bytes.Buffer)
		if !templ_7745c5c3_IsBuffer {
			templ_7745c5c3_Buffer = templ.GetBuffer()
			defer templ.ReleaseBuffer(templ_7745c5c3_Buffer)
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var1 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var1 == nil {
			templ_7745c5c3_Var1 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<div class=\"postsTemplate\"><style>\r\n                table {\r\n                    width: 100%;\r\n                    border-collapse: collapse;\r\n                }\r\n                th, td {\r\n                    padding: 12px;\r\n                    border: 1px solid #ddd;\r\n                    text-align: left;\r\n                }\r\n                th {\r\n                    background-color: #f2f2f2;\r\n                }\r\n                tr:nth-child(even) {\r\n                    background-color: #f9f9f9;\r\n                }\r\n    </style><div class=\"postsTemplatePost\"><table border=\"1\"><tr><th>Stock Name</th><th>Buying Price</th><th>Target Price</th><th>Exchange</th><th>Current Price</th><th>Comments</th></tr>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		for _, p := range posts {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<tr><td>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var2 string
			templ_7745c5c3_Var2, templ_7745c5c3_Err = templ.JoinStringErrs(p.Stock_name)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 35, Col: 38}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var2))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var3 string
			templ_7745c5c3_Var3, templ_7745c5c3_Err = templ.JoinStringErrs(p.Current_price)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 36, Col: 41}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var3))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var4 string
			templ_7745c5c3_Var4, templ_7745c5c3_Err = templ.JoinStringErrs(p.Target_price)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 37, Col: 40}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var4))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var5 string
			templ_7745c5c3_Var5, templ_7745c5c3_Err = templ.JoinStringErrs(p.Exchange)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 38, Col: 36}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var5))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td class=\"current-price\" hx-get=\"")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var6 string
			templ_7745c5c3_Var6, templ_7745c5c3_Err = templ.JoinStringErrs("/stocks?symbol=" + p.Stock_name + "&exchange=" + p.Exchange)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 39, Col: 115}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var6))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("\" hx-target=\"this\" hx-trigger=\"load\">Loading prices...</td><td>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var7 string
			templ_7745c5c3_Var7, templ_7745c5c3_Err = templ.JoinStringErrs(p.Comments)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 43, Col: 36}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var7))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td></tr>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</table></div><script>\r\n        function calculateGrowth(element) {\r\n            const row = element.closest('tr');\r\n            const buyingPrice = parseFloat(row.querySelector('.buying-price').textContent);\r\n            const currentPrice = parseFloat(element.textContent);\r\n            const growthElement = row.querySelector('.growth');\r\n            \r\n            if (!isNaN(buyingPrice) && !isNaN(currentPrice)) {\r\n                const growth = currentPrice - buyingPrice;\r\n                const growthPercentage = (growth / buyingPrice) * 100;\r\n                growthElement.textContent = growth.toFixed(2) + ' (' + growthPercentage.toFixed(2) + '%)';\r\n                \r\n                // Optionally, add color coding\r\n                if (growth > 0) {\r\n                    growthElement.style.color = 'green';\r\n                } else if (growth < 0) {\r\n                    growthElement.style.color = 'red';\r\n                }\r\n            } else {\r\n                growthElement.textContent = 'N/A';\r\n            }\r\n            console.log(growthElement)\r\n        }\r\n    </script></div>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if !templ_7745c5c3_IsBuffer {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteTo(templ_7745c5c3_W)
		}
		return templ_7745c5c3_Err
	})
}

func AdminPosts(posts map[string]Posts) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, templ_7745c5c3_W io.Writer) (templ_7745c5c3_Err error) {
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templ_7745c5c3_W.(*bytes.Buffer)
		if !templ_7745c5c3_IsBuffer {
			templ_7745c5c3_Buffer = templ.GetBuffer()
			defer templ.ReleaseBuffer(templ_7745c5c3_Buffer)
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var8 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var8 == nil {
			templ_7745c5c3_Var8 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<div class=\"postsTemplate\"><style>\r\n                table {\r\n                    width: 100%;\r\n                    border-collapse: collapse;\r\n                }\r\n                th, td {\r\n                    padding: 12px;\r\n                    border: 1px solid #ddd;\r\n                    text-align: left;\r\n                }\r\n                th {\r\n                    background-color: #f2f2f2;\r\n                }\r\n                tr:nth-child(even) {\r\n                    background-color: #f9f9f9;\r\n                }\r\n\r\n                .delete-btn {\r\n                    background-color: red;\r\n                    color: white;\r\n                    border: none;\r\n                    cursor: pointer;\r\n                    padding: 8px;\r\n                    text-align: center;\r\n                    text-decoration: none;\r\n                    display: inline-block;\r\n                    font-size: 16px;\r\n                    border-radius: 4px;\r\n                }\r\n                .delete-btn:hover {\r\n                    background-color: darkred;\r\n                }\r\n                .delete-icon {\r\n                    margin-right: 8px;\r\n                }\r\n                tr.htmx-swapping td {\r\n                opacity: 0;\r\n                transition: opacity 1s ease-out;\r\n                }\r\n\r\n    </style><div class=\"postsTemplatePost\"><table border=\"1\"><tr><th>Stock Name</th><th>Buying Price</th><th>Target Price</th><th>Exchange</th><th>Current Price</th><th>Comments</th></tr>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		for _, p := range posts {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<tr hx-target=\"closest tr\" hx-swap=\"outerHTML swap:1s\"><td class=\"stock-name\" name=\"stock_name\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var9 string
			templ_7745c5c3_Var9, templ_7745c5c3_Err = templ.JoinStringErrs(p.Stock_name)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 130, Col: 75}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var9))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td class=\"buying-price\" name=\"buying_price\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var10 string
			templ_7745c5c3_Var10, templ_7745c5c3_Err = templ.JoinStringErrs(p.Current_price)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 131, Col: 82}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var10))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td class=\"target-price\" name=\"target_price\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var11 string
			templ_7745c5c3_Var11, templ_7745c5c3_Err = templ.JoinStringErrs(p.Target_price)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 132, Col: 81}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var11))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td class=\"exchange\" name=\"exchange\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var12 string
			templ_7745c5c3_Var12, templ_7745c5c3_Err = templ.JoinStringErrs(p.Exchange)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 133, Col: 68}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var12))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td class=\"current-price\" hx-get=\"")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var13 string
			templ_7745c5c3_Var13, templ_7745c5c3_Err = templ.JoinStringErrs("/stocks?symbol=" + p.Stock_name + "&exchange=" + p.Exchange)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 136, Col: 88}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var13))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("\" hx-target=\"this\" hx-trigger=\"load\" hx-on::after-request=\"calculateGrowth(this)\">Loading prices...</td><td class=\"comments\" name=\"comments\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var14 string
			templ_7745c5c3_Var14, templ_7745c5c3_Err = templ.JoinStringErrs(p.Comments)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 143, Col: 69}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var14))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td><button class=\"action-btn delete-btn\" hx-delete=\"/admin/deletePosts\" hx-params=\"*\">Delete</button></td></tr>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</table></div><script>\r\n        function calculateGrowth(element) {\r\n            const row = element.closest('tr');\r\n            const buyingPrice = parseFloat(row.querySelector('.buying-price').textContent);\r\n            const currentPrice = parseFloat(row.querySelector('.current-price').textContent);\r\n            const growthElement = row.querySelector('.growth');\r\n            \r\n            if (!isNaN(buyingPrice) && !isNaN(currentPrice)) {\r\n                const growth = currentPrice - buyingPrice;\r\n                const growthPercentage = (growth / buyingPrice) * 100;\r\n                growthElement.textContent = growth.toFixed(2) + ' (' + growthPercentage.toFixed(2) + '%)';\r\n                \r\n                // Optionally, add color coding\r\n                if (growth > 0) {\r\n                    growthElement.style.color = 'green';\r\n                } else if (growth < 0) {\r\n                    growthElement.style.color = 'red';\r\n                }\r\n            } else {\r\n                growthElement.textContent = 'N/A';\r\n            }\r\n        }\r\n    </script></div>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if !templ_7745c5c3_IsBuffer {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteTo(templ_7745c5c3_W)
		}
		return templ_7745c5c3_Err
	})
}

func NewsTemplate(news map[string]News) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, templ_7745c5c3_W io.Writer) (templ_7745c5c3_Err error) {
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templ_7745c5c3_W.(*bytes.Buffer)
		if !templ_7745c5c3_IsBuffer {
			templ_7745c5c3_Buffer = templ.GetBuffer()
			defer templ.ReleaseBuffer(templ_7745c5c3_Buffer)
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var15 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var15 == nil {
			templ_7745c5c3_Var15 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<div class=\"newsTemplate\"><style>\r\n\r\n                table {\r\n                    width: 100%;\r\n                    border-collapse: collapse;\r\n                }\r\n                th, td {\r\n                    padding: 12px;\r\n                    border: 1px solid #ddd;\r\n                    text-align: left;\r\n                }\r\n                th {\r\n                    background-color: #f2f2f2;\r\n                }\r\n                tr:nth-child(even) {\r\n                    background-color: #f9f9f9;\r\n                }\r\n    </style><div class=\"newsTemplatePost\"><table border=\"1\"><tr><th>News</th><th>Links</th></tr>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		for _, p := range news {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<tr><td>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var16 string
			templ_7745c5c3_Var16, templ_7745c5c3_Err = templ.JoinStringErrs(p.New)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 207, Col: 31}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var16))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td><a href=\"{p.Link}\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var17 string
			templ_7745c5c3_Var17, templ_7745c5c3_Err = templ.JoinStringErrs(p.Link)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 208, Col: 51}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var17))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</a></td></tr>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</table></div></div>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if !templ_7745c5c3_IsBuffer {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteTo(templ_7745c5c3_W)
		}
		return templ_7745c5c3_Err
	})
}

func AdminNews(news map[string]News) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, templ_7745c5c3_W io.Writer) (templ_7745c5c3_Err error) {
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templ_7745c5c3_W.(*bytes.Buffer)
		if !templ_7745c5c3_IsBuffer {
			templ_7745c5c3_Buffer = templ.GetBuffer()
			defer templ.ReleaseBuffer(templ_7745c5c3_Buffer)
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var18 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var18 == nil {
			templ_7745c5c3_Var18 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<div class=\"newsTemplate\"><style>\r\n                table {\r\n                    width: 100%;\r\n                    border-collapse: collapse;\r\n                }\r\n                th, td {\r\n                    padding: 12px;\r\n                    border: 1px solid #ddd;\r\n                    text-align: left;\r\n                }\r\n                th {\r\n                    background-color: #f2f2f2;\r\n                }\r\n                tr:nth-child(even) {\r\n                    background-color: #f9f9f9;\r\n                }\r\n\r\n                .delete-btn {\r\n                    background-color: red;\r\n                    color: white;\r\n                    border: none;\r\n                    cursor: pointer;\r\n                    padding: 8px;\r\n                    text-align: center;\r\n                    text-decoration: none;\r\n                    display: inline-block;\r\n                    font-size: 16px;\r\n                    border-radius: 4px;\r\n                }\r\n                .delete-btn:hover {\r\n                    background-color: darkred;\r\n                }\r\n                .delete-icon {\r\n                    margin-right: 8px;\r\n                }\r\n                tr.htmx-swapping td {\r\n                opacity: 0;\r\n                transition: opacity 1s ease-out;\r\n                }\r\n\r\n    </style><div class=\"newsTemplatePost\"><table border=\"1\"><tr><th>News</th><th>Links</th></tr>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		for _, p := range news {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<tr hx-confirm=\"Are you sure?\" hx-target=\"closest tr\" hx-swap=\"outerHTML swap:1s\"><td class=\"stock-name\" name=\"news\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var19 string
			templ_7745c5c3_Var19, templ_7745c5c3_Err = templ.JoinStringErrs(p.New)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 268, Col: 62}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var19))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td class=\"current-price\" name=\"links\">")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			var templ_7745c5c3_Var20 string
			templ_7745c5c3_Var20, templ_7745c5c3_Err = templ.JoinStringErrs(p.Link)
			if templ_7745c5c3_Err != nil {
				return templ.Error{Err: templ_7745c5c3_Err, FileName: `table.templ`, Line: 269, Col: 67}
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var20))
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</td><td><button class=\"action-btn delete-btn\" hx-delete=\"/admin/deleteNews\" hx-params=\"*\">Delete</button></td></tr>")
			if templ_7745c5c3_Err != nil {
				return templ_7745c5c3_Err
			}
		}
		_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</table></div></div>")
		if templ_7745c5c3_Err != nil {
			return templ_7745c5c3_Err
		}
		if !templ_7745c5c3_IsBuffer {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteTo(templ_7745c5c3_W)
		}
		return templ_7745c5c3_Err
	})
}
