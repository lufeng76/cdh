r='\e[31m'
g='\e[32m'
n='\e[0m'

function say() {
  echo -e "${g}$1${n}"
}

# say "${r}This is red, ${g}this is green, and ${n}this is normal"