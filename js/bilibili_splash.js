function modify(a){try{a.data.pull_interval+=432e3,a.data.list=[],a.data.show.length>=0&&(a.data.show=[a.data.show[0]],a.data.show[0].stime+=432e3,a.data.show[0].etime+=432e3,a.data.show[0].splash_content=[],a.data.keep_ids=[a.data.show[0].id])}catch(t){a={}}return a}let body=$response.body;body=modify(JSON.parse(body)),$done({body:JSON.stringify(body)});