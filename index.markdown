---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

layout: post
---


 {% for category in site.categories %}
     <div class="catbloc" id="{{ category | first | remove:' ' }}">
          <h2>{{ category | first }}</h2>

          <ul>
             {% for posts in category %}
               {% for post in posts %}
                 {% if post.url %}
                  <li>
                    <a href="{{ post.url }}">
                      <time>{{ post.date | date: "%-d %B %Y" }}</time>
                      {{ post.title }}
                    </a>
                  </li>
                {% endif %}
              {% endfor %}
            {% endfor %}
         </ul>
     </div>
 {% endfor %}