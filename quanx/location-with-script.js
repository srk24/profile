/** 
 * @supported http://ip-api.com/json
 * @sample https://github.com/crossutility/Quantumult-X/raw/master/sample-location-with-script.js
 *
 * geo_location_checker=http://ip-api.com/json?fields=11024, https://github.com/srk24/profile/raw/master/quanx/location-with-script.min.js
 */

if ($response.statusCode !== 200) { let r = $done(Null) }

const obj = JSON.parse($response.body)
const title = obj.city
const subtitle = obj.isp
const ip = obj.query
const description = ip + '\n' + obj.timezone + '\n' + obj.as

$done({ title, subtitle, ip, description })
